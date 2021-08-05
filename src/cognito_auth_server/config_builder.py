#!/usr/bin/env python3.8
from json import (
    loads,
    dumps,
    dump
)
from os import (
    getuid,
    getgid,
    path,
    chmod,
    chown
)
from shutil import copyfile
from textwrap import dedent
from utils import validate_config
from exceptions import (
    InvalidChoiceException,
    InvalidTypeException,
    RequiredException
)

service_name = None
install_dir = None
socket_path = None
log_path = None
config = {
    "global": {},
    "cognito": {},
    "server": {}
}


def init():
    global service_name, install_dir, socket_path, log_path, config

    while not service_name:
        service_name = input("Give the service a name >")

    config["global"]["service_name"] = service_name

    if install_dir is None:
        install_dir = input("Select an installation directory >")

    while not path.isdir(install_dir):
        print(f"Directory {install_dir} does not exist.")
        install_dir = input("Select an installation directory >")

    socket_path = f"{install_dir}/run/{service_name}.sock"
    log_path = f"{install_dir}/logs/{service_name}.log"


global_template = None
server_templates = None
cognito_template = None


def gen_templates():
    global global_template, server_templates, cognito_template
    global_template = {
        "server_type": {"type": str, "required": True, "choices": ["unix", "tcp", "http"], "default": "unix"},
        "credential_type": {"type": str, "required": True, "choices": ["iam", "tokens"], "default": "tokens"},
        "log_path": {"type": str, "default": log_path, "required": True},
        "user": {"type": int, "default": getuid(), "required": True},
        "group": {"type": int, "default": getgid(), "required": True},
        "auth_secret": {"type": str, "required": False}
    }
    server_templates = {
        "tcp": {
            "host": {"default": "127.0.0.1", "type": str},
            "port": {"default": 5500, "type": int}
        },
        "http": {
            "host": {"default": "127.0.0.1", "type": str},
            "port": {"default": 8080, "type": int}
        },
        "unix": {
            "permissions": {"type": int, "default": 600},
            "socket_path": {"type": str, "default": socket_path, "required": True}
        }
    }

    cognito_template = {
        "aws_default_region": {"default": "us-east-1", "type": str},
        "username": {"type": str, "required": True},
        "password": {"type": str, "required": True},
        "app_id": {"type": str, "required": True},
        "user_pool_id": {"type": str, "required": True},
        "identity_pool_id": {"type": str},
        "role_arn": {"type": str},
        "role_session_name": {"type": str},
        "auth_flow": {"type": str, "default": "enhanced", "choices": ["classic", "enhanced"]},
        "metadata": {"type": dict},
        "role_expiry_time": {"type": int, "default": 900},
        "auth_type": {"type": str, "default": "user_srp", "choices": {"user_srp", "user_password"}}
    }

    full_template = {
        "global": global_template,
        "cognito": cognito_template,
        "server": server_templates
    }

    return full_template


def ask_question(
    prompt,
    field,
    field_type,
    required=False,
    default=None,
    choices=[],
):
    val = input(prompt) or default or None

    if required is True and val is None:
        raise RequiredException(f"Value {field} is required")

    if val is not None:
        if choices and val not in choices:
            raise InvalidChoiceException(f"Invalid value for {field}. Valid choices: {'/'.join(choices)}")
        try:
            if field_type == dict:
                val = loads(val)
            else:
                val = field_type(val)
        except Exception:
            raise InvalidTypeException(f"Invalid type for {field}")

    return val


def handle_template(template, directive, skip_empty=False):
    global config
    for k, arg in template.items():
        default_val = arg.get("default")
        default_msg = f" (default: {default_val}) " if default_val else " "
        required = " (required) " if arg.get("required") is True else " "
        valid_opts = "[" + "/".join(arg["choices"]) + "]" if arg.get("choices") else ""
        arg_type = arg["type"]().__class__.__name__
        msg = f"Enter{required}{arg_type} value{default_msg}for {k} {valid_opts}> "
        error = False
        try:
            val = ask_question(
                msg,
                k,
                arg.get("type"),
                required=arg.get("required", False),
                default=default_val,
                choices=arg.get("choices", [])
            )
        except (RequiredException, InvalidChoiceException, InvalidTypeException) as e:
            print(e)
            error = True
            val = None

        if not error:
            if val is None and skip_empty is True and not arg.get("required", False):
                continue

        while (
            error
            or val is None
            and (skip_empty is False or arg.get("required") is True)
        ):
            try:
                val = ask_question(
                    msg,
                    k,
                    arg.get("type"),
                    required=arg.get("required", False),
                    default=default_val,
                    choices=arg.get("choices", [])
                )
                error = False
            except (RequiredException, InvalidChoiceException, InvalidTypeException) as e:
                print(e)
                error = True
                val = None

        if val is not None:
            config[directive][k] = val


def build_config():
    init()
    gen_templates()
    handle_template(global_template, directive="global")
    server_type = config["global"]["server_type"]
    server_template = server_templates[server_type]
    handle_template(server_template, directive="server")
    handle_template(cognito_template, directive="cognito", skip_empty=True)
    validate_config(config)
    print(dumps(config, indent=2))

    print("""

    """)
    write_file = input(f"Write file to ./{service_name}.json? >")
    while write_file not in ("yes", "no"):
        print(f"Unexpected answer {write_file}")
        input("Write file to ./{service_name}.json? >")

    if write_file == "yes":
        try:
            with open(f"./{service_name}.json", "w+") as f:
                dump(config, f, indent=2)
        except Exception as e:
            print(f"""
                ERROR: Could not write config to file.
                {str(e)}
            """)

    do_install = input("Would you like to install the server using this config? [yes/no]")

    while do_install not in ("yes", "no"):
        do_install = input("Would you like to install the server using this config? [yes/no]")

    if do_install == "yes":
        from install import (
            make_dirs,
            make_systemd,
            make_profile
        )

        make_dirs(install_dir)
        exec_path = f"{install_dir}/bin/cognito-auth-server"
        copyfile(f"{path.dirname(path.abspath(__file__))}/scripts/cognito-auth-server", exec_path)
        chmod(exec_path, 0o700)
        config_path = f'{install_dir}/{service_name}.json'
        if path.isfile(config_path):
            print("A config for this service name already exists.")
            exit()

        with open(config_path, "w+") as f:
            dump(config, f, indent=2)

        chmod(config_path, 0o400)
        chown(config_path, config["global"]["user"], config["global"]["group"])

        template = make_systemd(config, config_path, install_dir, dry_run=True)
        print(dedent(f"""
        ### SYSTEMD SERVICE FILE ###
        {template}
        """))

        if config["global"]["credential_type"] == "iam":
            print("Creating systemd template....")
            profile = make_profile(config, dry_run=True)
            print(dedent(f"""
            ### AWS PROFILE ###
            {profile}
            """))
            print(profile)


if __name__ == "__main__":
    build_config()
