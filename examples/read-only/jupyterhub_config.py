c = get_config()  # noqa

# define custom scopes so they can be assigned to users
# these could be

c.JupyterHub.custom_scopes = {
    "custom:jupyter_server:read:*": {
        "description": "read-only access to your server",
    },
    "custom:jupyter_server:write:*": {
        "description": "access to modify files on your server. Does not include execution.",
        "subscopes": ["custom:jupyter_server:read:*"],
    },
    "custom:jupyter_server:execute:*": {
        "description": "Full permissions on servers, including execution.",
        "subscopes": [
            "custom:jupyter_server:write:*",
            "custom:jupyter_server:read:*",
        ],
    },
    "custom:jupyter_server:read:api": {
        "description": "Read permissions on single-user /api/status endpoint",
    },
}

c.JupyterHub.load_roles = [
    # grant specific users read-only access to all servers
    {
        "name": "status-only-all",
        "scopes": [
            "access:servers",
            "custom:jupyter_server:read:api",
        ],
        "services": ["status-check"],
    },
    # all users have full access to their own servers
    # execute permissions are now required to _do_ anything with a server,
    # as granular permissions have been enabled
    {
        "name": "user",
        "scopes": [
            "custom:jupyter_server:execute:*!user",
            "self",
        ],
    },
]

c.JupyterHub.services = [
    {
        "name": "status-check",
        "api_token": "abc123secret",
    },
]

# servers request access to themselves

c.Spawner.oauth_client_allowed_scopes = [
    "access:servers!server",
    "custom:jupyter_server:read:*!server",
    "custom:jupyter_server:execute:*!server",
]

# enable the jupyter-server extension
c.Spawner.environment = {
    "JUPYTERHUB_SINGLEUSER_EXTENSION": "1",
}

from pathlib import Path

here = Path(__file__).parent.resolve()

# load the server config that enables granular permissions
c.Spawner.args = [
    f"--config={here}/jupyter_server_config.py",
]


# example boilerplate: dummy auth/spawner
c.JupyterHub.authenticator_class = 'dummy'
c.JupyterHub.spawner_class = 'simple'
c.JupyterHub.ip = '127.0.0.1'
