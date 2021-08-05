#!/usr/bin/env python3.8
from json import loads, load, dumps
from copy import deepcopy
from getpass import getuser
from os import (
    path,
    getuid,
    getgid,
    getcwd,
)
from jsonschema import validate
from cognitoinator import get_profile
from cognitoinator.providers import CognitoConfig
from cognito_auth_server.server import (
    WebServer,
    TCPServer,
    SocketServer,
    logger
)

config_from_env = False
default_install_dir = "/opt/cognito_auth_server"
default_service_name = "cognitod"

arg_map = {
    "tcp": {
        "port": "-P",
        "host": "-H"
    },
    "unix": {
        "permissions": "-p",
        "socket_path": "-s"
    },
    "http": {
        "port": "-P",
        "host": "-H"
    }
}

defaults = {
    "global": {
        "user": getuid(),
        "group": getgid(),
        "server_type": "unix",
        "credential_type": "iam",
        "service_name": "cognitod",
        "auth_secret": None
    },
    "cognito": {},
    "server": {
        "port": 5500,
        "host": "127.0.0.1",
        "permissions": 700,
        "socket_path": f"{getcwd()}/cognito_server.sock"
    }
}


def validate_config(config):

    def do_validation(config, schema):
        try:
            validate(config, schema)
        except Exception as e:
            msg = f"""
            ERROR: {e.message}
            PATH: {".".join(list(e.absolute_path)) or "<root object>"}
            """
            raise Exception(msg)

    if "global" not in config:
        raise Exception("Missing 'globals' directive in config")

    global_schema = {
        "type": "object",
        "properties": {
            "credential_type": {"type": "string"},
            "server_type": {"type": "string"},
            "service_name": {"type": "string"},
            "user": {"type": "integer"},
            "group": {"type": "integer"},
            "auth_secret": {"type": ["string", "null"]}
        },
        "required": [
            "server_type",
            "credential_type",
            "user",
            "group"
        ],
        "additionalAttributes": False
    }

    do_validation(config["global"], global_schema)

    unix_schema = {
        "type": "object",
        "properties": {
            "socket_path": {"type": "string"},
            "permissions": {"type": "integer"}
        },
        "required": [
            "socket_path",
            "permissions",
        ],
        "additionalProperties": False
    }

    http_schema = {
        "type": "object",
        "properties": {
            "port": {"type": "integer"},
            "host": {"type": "string"}
        },
        "required": [
            "port",
            "host"
        ],
        "additionalProperties": False
    }

    tcp_schema = {
        "type": "object",
        "properties": {
            "port": {"type": "integer"},
            "host": {"type": "string"}
        },
        "required": [
            "port",
            "host"
        ],
        "additionalProperties": False
    }

    server_schemas = {
        "tcp": tcp_schema,
        "http": http_schema,
        "unix": unix_schema
    }

    cognito_schema = {
        "type": "object",
        "properties": {
            "app_id": {"type": "string"},
            "password": {"type": "string"},
            "username": {"type": "string"},
            "user_pool_id": {"type": "string"},
            "aws_default_region": {"type": "string"},
            "identity_pool_id": {"type": "string"},
            "role_arn": {"type": "string"},
            "role_session_name": {"type": "string"},
            "auth_flow": {"type": "string"},
            "auth_type": {"type": "string"},
            "metadata": {"type": ["string", "object"]},
            "role_expiry_time": {"type": "integer"},
            "region": {"type": "string"},
            "region_name": {"type": "string"}
        },
        "required": [
            "app_id",
            "password",
            "username",
            "user_pool_id"
        ],
        "additionalProperties": False
    }

    server_type = config["global"]["server_type"]

    try:
        server_schema = server_schemas[server_type]
    except KeyError:
        raise ValueError(f"Unknown server type {server_type}")

    config_schema = {
        "type": "object",
        "properties": {
            "global": global_schema,
            "server": server_schema,
            "cognito": cognito_schema
        },
        "additionalProperties": False,
        "required": [
            "global",
            "server",
            "cognito"
        ]
    }

    do_validation(config, config_schema)


def validate_args(args, parser=None):
    msg = None

    allowed_vars = arg_map[args["server_type"]]
    ignored = (
        "use_env",
        "cognito_profile",
        "config_file",
        "credential_type",
        "server_type",
        "use_env",
        "install_dir",
        "server_name",
        "service_name"
        "retries",
        "auth_secret"
    )
    passed_args = [
        x for x in args
        if x not in ignored
        and args[x] is not None
    ]

    for x in passed_args:
        if x not in allowed_vars:
            flags = ",".join(list(arg_map[args["server_type"]].values()))
            msg = f"""
                Invalid argument --{x}
                Server type {args["server_type"]} only accepts arguments {flags}"
            """

    if msg is not None:
        if parser:
            raise parser.error(msg)
        else:
            raise Exception(msg)


def get_runtime_config(args):
    config = defaults
    if config_file := args.get("config_file"):
        try:
            with open(config_file, "r") as f:
                user_config = load(f)
        except Exception as e:
            logger.error(f"Could not load config file {args['config_file']}: {e}")
            exit()

        config_copy = deepcopy(config)
        for directive, vals in user_config.items():
            if directive in config_copy:
                for k, v in vals.items():
                    config[directive][k] = v

        if "cognito" in user_config:
            config["cognito"] = CognitoConfig(config["cognito"])

    if args.get("cognito_profile") is not None:
        user = args.get("user") or getuser()
        credentials_file = args.get("cognito_credentials_file") or f"{path.expanduser(f'~{user}')}/.aws/cognito_credentials"
        config["cognito"].update(
            get_profile(
                args["cognito_profile"],
                credentials_file
            )
        )

    if args.get("use_env", False):
        cleaned_config = {
            k: v for k, v in CognitoConfig(config["cognito"]).items()
            if v is not None
        }
        config["cognito"].update(cleaned_config)
    for directive, vals in defaults.items():
        for k, v in args.items():
            if v is not None and k in config[directive]:
                config[directive][k] = v

    server_type = config["global"]["server_type"]
    allowed_server_args = arg_map[server_type]
    config_copy = deepcopy(config)

    for arg in config_copy["server"]:
        if arg not in allowed_server_args:
            del config["server"][arg]

    config["cognito"] = dict(config["cognito"])
    print(dumps(config, indent=4))
    validate_config(config)
    return dict(config)


def start_server(config: dict):
    """
    Acts as a type of factory, configuring and starting the correct server
    class based in cmdline args.
    """
    server_type = config["global"]["server_type"]

    validate_config(config)

    servers = {
        "unix": SocketServer,
        "tcp": TCPServer,
        "http": WebServer
    }

    try:
        server = servers[server_type](config)
    except KeyError:
        raise Exception(f"Unknown server type {server_type}")

    try:
        server.start()
    except Exception as e:
        print(f"Could not start server: {e}")
        raise e
