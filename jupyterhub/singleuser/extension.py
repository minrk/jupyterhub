"""
Integrate JupyterHub auth with Jupyter Server as an Extension

Requires Jupyter Server 2.0, which in turn requires Python 3.7
"""

from __future__ import annotations

import asyncio
import json
import os
import random
from datetime import timezone
from functools import wraps
from unittest import mock
from urllib.parse import urlparse

from jupyter_server.auth import Authorizer, IdentityProvider, User
from jupyter_server.auth.logout import LogoutHandler
from jupyter_server.extension.application import ExtensionApp
from jupyter_server.serverapp import ServerApp
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httputil import url_concat
from traitlets import Any, Instance, Integer, Unicode, default

from jupyterhub._version import __version__, _check_version
from jupyterhub.services.auth import HubOAuth, HubOAuthCallbackHandler
from jupyterhub.utils import (
    exponential_backoff,
    isoformat,
    make_ssl_context,
    url_path_join,
)


class JupyterHubLogoutHandler(LogoutHandler):
    def get(self):
        hub_auth = self.identity_provider.hub_auth
        # clear single-user cookie
        hub_auth.clear_cookie(self)
        # redirect to hub to clear the rest
        self.redirect(hub_auth.hub_host + url_path_join(hub_auth.hub_prefix, "logout"))


class JupyterHubUser(User):
    """Subclass jupyter_server User to store JupyterHub user info"""

    # not dataclass fields,
    # so these aren't returned in the identity model via the REST API.
    # The could be, though!
    hub_user: dict

    def __init__(self, hub_user):
        self.hub_user = hub_user
        super().__init__(username=self.hub_user["name"])


class JupyterHubOAuthCallbackHandler(HubOAuthCallbackHandler):
    """Callback handler for completing OAuth with JupyterHub"""

    def initialize(self, hub_auth):
        self.hub_auth = hub_auth


class JupyterHubIdentityProvider(IdentityProvider):
    """Identity Provider for JupyterHub OAuth

    Replacement for JupyterHub's HubAuthenticated mixin
    """

    logout_handler_class = JupyterHubLogoutHandler

    hub_auth = Instance(HubOAuth)

    @property
    def token(self):
        return self.hub_auth.api_token

    token_generated = False

    @default("hub_auth")
    def _default_hub_auth(self):
        # HubAuth gets most of its config from the environment
        return HubOAuth(parent=self)

    def _patch_get_login_url(self, handler):
        original_get_login_url = handler.get_login_url

        def get_login_url():
            """Return the Hub's login URL, to begin login redirect"""
            login_url = self.hub_auth.login_url
            # add state argument to OAuth url
            state = self.hub_auth.set_state_cookie(
                handler, next_url=handler.request.uri
            )
            login_url = url_concat(login_url, {'state': state})
            # temporary override at setting level,
            # to allow any subclass overrides of get_login_url to preserve their effect;
            # for example, APIHandler raises 403 to prevent redirects
            with mock.patch.dict(
                handler.application.settings, {"login_url": login_url}
            ):
                self.log.debug("Redirecting to login url: %s", login_url)
                return original_get_login_url()

        handler.get_login_url = get_login_url

    async def get_user(self, handler):
        if hasattr(handler, "_jupyterhub_user"):
            return handler._jupyterhub_user
        self._patch_get_login_url(handler)
        user = await self.hub_auth.get_user(handler, sync=False)
        if user is None:
            handler._jupyterhub_user = None
            return None
        # check access scopes - don't allow even authenticated
        # users with no access to this service past this stage.
        self.log.debug(
            f"Checking user {user['name']} with scopes {user['scopes']} against {self.hub_auth.oauth_scopes}"
        )
        scopes = self.hub_auth.check_scopes(self.hub_auth.oauth_scopes, user)
        if scopes:
            self.log.debug(f"Allowing user {user['name']} with scopes {scopes}")
        else:
            self.log.warning(f"Not allowing user {user['name']}")
            return None
        handler._jupyterhub_user = JupyterHubUser(user)
        return handler._jupyterhub_user

    def get_handlers(self):
        """Register our OAuth callback handler"""
        return [
            ("/logout", self.logout_handler_class),
            (
                "/oauth_callback",
                JupyterHubOAuthCallbackHandler,
                {"hub_auth": self.hub_auth},
            ),
        ]

    def validate_security(self, app, ssl_options=None):
        """Prevent warnings about security from base class"""
        return

    def page_config_hook(self, handler, page_config):
        """JupyterLab page config hook

        Adds JupyterHub info to page config.

        Places the JupyterHub API token in PageConfig.token.

        Only has effect on jupyterlab_server >=2.9
        """
        user = handler.current_user
        # originally implemented in jupyterlab's LabApp
        page_config["hubUser"] = user.name if user else ""
        page_config["hubPrefix"] = hub_prefix = self.hub_auth.hub_prefix
        page_config["hubHost"] = self.hub_auth.hub_host
        page_config["shareUrl"] = url_path_join(hub_prefix, "user-redirect")
        page_config["hubServerName"] = os.environ.get("JUPYTERHUB_SERVER_NAME", "")
        page_config["token"] = self.hub_auth.get_token(handler) or ""
        return page_config


class JupyterHubAuthorizer(Authorizer):
    """Authorizer that looks for permissions in JupyterHub scopes"""

    # TODO: https://github.com/jupyter-server/jupyter_server/pull/830
    hub_auth = Instance(HubOAuth)

    @default("hub_auth")
    def _default_hub_auth(self):
        # HubAuth gets most of its config from the environment
        return HubOAuth(parent=self)

    def is_authorized(self, handler, user, action, resource):
        # This is where we would implement granular scope checks,
        # but until then,
        # since the IdentityProvider doesn't allow users without access scopes,
        # there's no further check to make.
        # This scope check is redundant
        have_scopes = self.hub_auth.check_scopes(
            self.hub_auth.oauth_scopes, user.hub_user
        )
        self.log.debug(
            f"{user.username} has permissions {have_scopes} required to {action} on {resource}"
        )
        return bool(have_scopes)


def _fatal_errors(f):
    """Decorator to make errors fatal to the server app

    Ensures our extension is loaded or the server exits,
    rather than starting a server without jupyterhub auth enabled.
    """

    @wraps(f)
    def wrapped(self, *args, **kwargs):
        try:
            r = f(self, *args, **kwargs)
        except Exception:
            self.log.exception("Failed to load JupyterHubSingleUser server extension")
            self.exit(1)

    return wrapped


class JupyterHubSingleUser(ExtensionApp):
    """Jupyter Server extension entrypoint.

    Enables JupyterHub authentication
    and some JupyterHub-specific configuration from environment variables

    Server extensions are loaded before the rest of the server is set up
    """

    name = app_namespace = "jupyterhub-singleuser"
    load_other_extensions = True  # TODO: configurable?

    # Most of this is _copied_ from the SingleUserNotebookApp mixin,
    # which will be deprecated over time
    # (i.e. once we can _require_ jupyter server 2.0)

    hub_auth = Instance(HubOAuth)

    @default("hub_auth")
    def _default_hub_auth(self):
        # HubAuth gets most of its config from the environment
        return HubOAuth(parent=self)

    # create dynamic default http client,
    # configured with any relevant ssl config
    hub_http_client = Any()

    @default('hub_http_client')
    def _default_client(self):
        ssl_context = make_ssl_context(
            self.hub_auth.keyfile,
            self.hub_auth.certfile,
            cafile=self.hub_auth.client_ca,
        )
        AsyncHTTPClient.configure(None, defaults={"ssl_options": ssl_context})
        return AsyncHTTPClient()

    async def check_hub_version(self):
        """Test a connection to my Hub

        - exit if I can't connect at all
        - check version and warn on sufficient mismatch
        """
        client = self.hub_http_client
        RETRIES = 5
        for i in range(1, RETRIES + 1):
            try:
                resp = await client.fetch(self.hub_api_url)
            except Exception:
                self.log.exception(
                    "Failed to connect to my Hub at %s (attempt %i/%i). Is it running?",
                    self.hub_api_url,
                    i,
                    RETRIES,
                )
                await asyncio.sleep(min(2**i, 16))
            else:
                break
        else:
            self.exit(1)

        hub_version = resp.headers.get('X-JupyterHub-Version')
        _check_version(hub_version, __version__, self.log)

    server_name = Unicode()

    @default('server_name')
    def _server_name_default(self):
        return os.environ.get('JUPYTERHUB_SERVER_NAME', '')

    hub_activity_url = Unicode(
        config=True, help="URL for sending JupyterHub activity updates"
    )

    @default('hub_activity_url')
    def _default_activity_url(self):
        return os.environ.get('JUPYTERHUB_ACTIVITY_URL', '')

    hub_activity_interval = Integer(
        300,
        config=True,
        help="""
        Interval (in seconds) on which to update the Hub
        with our latest activity.
        """,
    )

    @default('hub_activity_interval')
    def _default_activity_interval(self):
        env_value = os.environ.get('JUPYTERHUB_ACTIVITY_INTERVAL')
        if env_value:
            return int(env_value)
        else:
            return 300

    _last_activity_sent = Any(allow_none=True)

    async def notify_activity(self):
        """Notify jupyterhub of activity"""
        client = self.hub_http_client
        last_activity = self.web_app.last_activity()
        if not last_activity:
            self.log.debug("No activity to send to the Hub")
            return
        if last_activity:
            # protect against mixed timezone comparisons
            if not last_activity.tzinfo:
                # assume naive timestamps are utc
                self.log.warning("last activity is using naive timestamps")
                last_activity = last_activity.replace(tzinfo=timezone.utc)

        if self._last_activity_sent and last_activity < self._last_activity_sent:
            self.log.debug("No activity since %s", self._last_activity_sent)
            return

        last_activity_timestamp = isoformat(last_activity)

        async def notify():
            self.log.debug("Notifying Hub of activity %s", last_activity_timestamp)
            req = HTTPRequest(
                url=self.hub_activity_url,
                method='POST',
                headers={
                    "Authorization": f"token {self.hub_auth.api_token}",
                    "Content-Type": "application/json",
                },
                body=json.dumps(
                    {
                        'servers': {
                            self.server_name: {'last_activity': last_activity_timestamp}
                        },
                        'last_activity': last_activity_timestamp,
                    }
                ),
            )
            try:
                await client.fetch(req)
            except Exception:
                self.log.exception("Error notifying Hub of activity")
                return False
            else:
                return True

        await exponential_backoff(
            notify,
            fail_message="Failed to notify Hub of activity",
            start_wait=1,
            max_wait=15,
            timeout=60,
        )
        self._last_activity_sent = last_activity

    async def keep_activity_updated(self):
        if not self.hub_activity_url or not self.hub_activity_interval:
            self.log.warning("Activity events disabled")
            return
        self.log.info(
            "Updating Hub with activity every %s seconds", self.hub_activity_interval
        )
        while True:
            try:
                await self.notify_activity()
            except Exception as e:
                self.log.exception("Error notifying Hub of activity")
            # add 20% jitter to the interval to avoid alignment
            # of lots of requests from user servers
            t = self.hub_activity_interval * (1 + 0.2 * (random.random() - 0.5))
            await asyncio.sleep(t)

    def _log_app_versions(self):
        """Log application versions at startup

        Logs versions of jupyterhub and singleuser-server base versions (jupyterlab, jupyter_server, notebook)
        """
        self.log.info(
            f"Starting jupyterhub single-user server extension version {__version__}"
        )

    def load_config_file(self):
        """Load JupyterHub singleuser config from the environment"""
        self._log_app_versions()
        if not os.environ.get('JUPYTERHUB_SERVICE_URL'):
            raise KeyError("Missing required environment $JUPYTERHUB_SERVICE_URL")

        cfg = self.config.ServerApp
        cfg.identity_provider_class = JupyterHubIdentityProvider

        # disable some single-user features
        cfg.open_browser = False
        cfg.trust_xheaders = True
        cfg.quit_button = False
        cfg.port_retries = 0
        cfg.answer_yes = True
        self.config.FileContentsManager.delete_to_trash = False

        # load http server config from environment
        url = urlparse(os.environ['JUPYTERHUB_SERVICE_URL'])
        if url.port:
            cfg.port = url.port
        elif url.scheme == 'http':
            cfg.port = 80
        elif cfg.scheme == 'https':
            cfg.port = 443
        if url.hostname:
            cfg.ip = url.hostname
        else:
            cfg.ip = "127.0.0.1"

        cfg.base_url = os.environ.get('JUPYTERHUB_SERVICE_PREFIX') or '/'

        # load default_url at all kinds of priority,
        # to make sure it has the desired effect
        cfg.default_url = self.default_url = self.get_default_url()

        # Jupyter Server default: config files have higher priority than extensions,
        # by:
        # 1. load config files
        # 2. load extension config
        # 3. merge file config into extension config

        # we invert that by merging our extension config into server config before
        # they get merged the other way
        # this way config from this extension should always have highest priority
        self.serverapp.update_config(self.config)

    @default("default_url")
    def get_default_url(self):
        # 1. explicit via _user_ config (?)
        if 'default_url' in self.serverapp.config.ServerApp:
            default_url = self.serverapp.config.ServerApp.default_url
            self.log.info(f"Using default url from user config: {default_url}")
            return default_url

        # 2. explicit via JupyterHub admin config (c.Spawner.default_url)
        default_url = os.environ.get("JUPYTERHUB_DEFAULT_URL")
        if default_url:
            self.log.info(
                f"Using default url from environment $JUPYTERHUB_DEFAULT_URL: {default_url}"
            )
            return default_url

        # 3. look for known UI extensions
        # priority:
        # 1. lab
        # 2. nbclassic
        # 3. retro

        extension_points = self.serverapp.extension_manager.extension_points
        for name in ["lab", "retro", "nbclassic"]:
            if name in extension_points:
                default_url = extension_points[name].app.default_url
                if default_url and default_url != "/":
                    self.log.info(
                        f"Using default url from server extension {name}: {default_url}"
                    )
                    return default_url

        self.log.warning(
            "No default url found in config or known extensions, searching other extensions for default_url"
        )
        # 3. _any_ UI extension
        # 2. discover other extensions
        for (
            name,
            extension_point,
        ) in extension_points.items():
            app = extension_point.app
            if app is self or not app:
                continue
            default_url = app.default_url
            if default_url and default_url != "/":
                self.log.info(
                    f"Using default url from server extension {name}: {default_url}"
                )
                return default_url

        self.log.warning(
            "Found no extension with a default URL, UI will likely be unavailable"
        )
        return "/"

    @_fatal_errors
    def initialize(self, args=None):
        # initialize takes place after
        # 1. config has been loaded
        # 2. Configurables instantiated
        # 3. serverapp.web_app set up
        super().initialize()
        app = self.serverapp
        assert self.hub_auth.oauth_client_id
        assert self.hub_auth.api_token
        assert self.hub_auth.oauth_scopes
        app.web_app.settings[
            "page_config_hook"
        ] = app.identity_provider.page_config_hook

    @classmethod
    def make_serverapp(cls, **kwargs):
        """Instantiate the ServerApp

        Override to customize the ServerApp before it loads any configuration
        """
        serverapp = ServerApp.instance(**kwargs)

        return serverapp
        return cls.serverapp_class.instance(**kwargs)

    # BEGIN: copy initialize_server from https://github.com/jupyter-server/jupyter_server/pull/879
    # so we can override make_serverapp above

    @classmethod
    def initialize_server(cls, argv=None, load_other_extensions=True, **kwargs):
        """Creates an instance of ServerApp and explicitly sets
        this extension to enabled=True (i.e. superceding disabling
        found in other config from files).

        The `launch_instance` method uses this method to initialize
        and start a server.
        """
        jpserver_extensions = {cls.get_extension_package(): True}
        find_extensions = cls.load_other_extensions
        if "jpserver_extensions" in cls.serverapp_config:
            jpserver_extensions.update(cls.serverapp_config["jpserver_extensions"])
            cls.serverapp_config["jpserver_extensions"] = jpserver_extensions
            find_extensions = False
        serverapp = cls.make_serverapp(
            jpserver_extensions=jpserver_extensions, **kwargs
        )
        serverapp.aliases.update(cls.aliases)
        serverapp.initialize(
            argv=argv or [],
            starter_extension=cls.name,
            find_extensions=find_extensions,
        )
        return serverapp

    # END: copy initialize_server from https://github.com/jupyter-server/jupyter_server/pull/879


main = JupyterHubSingleUser.launch_instance

if __name__ == "__main__":
    main()
