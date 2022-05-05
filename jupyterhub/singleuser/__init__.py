"""JupyterHub single-user server entrypoints

Contains default notebook-app subclass and mixins
"""
import os

from .mixins import HubAuthenticatedHandler, make_singleuser_app

if os.environ.get("JUPYTERHUB_SINGLEUSER_EXTENSION", "") not in ("", "0"):
    from .extension import main
else:
    try:
        from .app import SingleUserNotebookApp, main
    except ImportError:
        # check for Jupyter Server 2.0 ?
        from .extension import main
    else:
        # backward-compatibility
        JupyterHubLoginHandler = SingleUserNotebookApp.login_handler_class
        JupyterHubLogoutHandler = SingleUserNotebookApp.logout_handler_class
        OAuthCallbackHandler = SingleUserNotebookApp.oauth_callback_handler_class
