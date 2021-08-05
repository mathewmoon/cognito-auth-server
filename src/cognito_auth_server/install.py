#!/usr/bin/env python3.8
from json import dump, load
from utils import (
    validate_args,
    get_config
)
from args import parse_args, parser
from os import (
    makedirs,
    system,
    path,
    getgid,
    getuid,
    chmod,
    chown

)
from systemd import BASE_TEMPLATE as SYSTEMD
from textwrap import dedent
from shutil import copyfile, which


def make_dirs(install_dir):
    try:
        makedirs(f"{install_dir}/logs")
    except FileExistsError:
        pass

    try:
        makedirs(f"{install_dir}/run")
    except FileExistsError:
        pass

    try:
        makedirs(f"{install_dir}/bin")
    except FileExistsError:
        pass


def make_config(user_config, args, install_dir):
    config_path = f'{install_dir}/{args["name"]}.json'

    if path.isfile(config_path):
        raise Exception("A config for this service name already exists.")

    if args.get("credentials"):
        print("yes")
        args["config_json"] = args["credentials"]
        del args["credentials"]

    cognito_config = get_config({
        **user_config["cognito"],
        **args
    })

    del args["config_json"]

    log_path = f'{install_dir}/{args["name"]}.log'

    server_config = {
        **{
            "server_type": args["server_type"] or "unix",
            "credential_type": "iam",
            "user": getuid(),
            "group": getgid(),
            "log_path": log_path,
            "name": args["name"]
        },
        **user_config["server"]
    }

    cmdline_args = {
        k: v for k, v in args.items()
        if v is not None
    }
    server_defaults = None  # get_server_defaults(install_dir=install_dir, service_name=args["name"])
    server_config.update(server_defaults[server_config["server_type"]])
    server_config.update(cmdline_args)

    config = {
        "cognito": cognito_config,
        "server": server_config
    }

    with open(config_path, "w+") as f:
        dump(config, f, indent=2)

    chown(config_path, server_config["user"], server_config["group"])
    chmod(config_path, 0o400)

    return config


def make_systemd(config, config_path, install_dir, dry_run=False):
    template_vars = {
        **config["server"],
        **config["global"],
        "config_path": config_path,
        "install_dir": install_dir
    }
    template = dedent(SYSTEMD.format(**template_vars))

    if not dry_run:
        with open(f'/etc/systemd/system/{config["global"]["service_name"]}.service', "w+") as f:
            f.write(template)
        if (
            system("systemctl daemon-reload"),
            system(f'systemctl enable {config["global"]["service_name"]}.service')
        ) != (0, 0):
            print("Installing systemd service failed.")

        if config["global"]["server_type"] in ("tcp", "unix") and which("nc") is None:
            print("""
            You will need to install OpenBSD netcat for the auth service to work.
            The version of netcat installed must support the -U option for unix
            domain sockets to work.
            """)

        if config["global"]["server_type"] == "http" and which("curl") is None:
            print("""
            You will need to install curl for the auth service to work.
            """)

    return template


def make_profile(config, dry_run=False):

    CMDS = {
        "unix": f'nc -U {config["server"].get("socket_path")}',
        "tcp": f'nc {config["server"].get("host")} {config["server"].get("port")}',
        "http": f'curl {config["server"].get("host")}:{config["server"].get("port")}'
    }
    user = config["global"]["user"]
    home = path.expanduser(f"~{user}")

    profile = dedent(f"""
    [{config["global"]["service_name"]}]
    credential_process: {CMDS[config["global"]["server_type"]]}
    """)

    credentials_path = f"{home}/.aws/credentials"

    if not dry_run:
        try:
            makedirs(f"{home}/.aws")
        except FileExistsError:
            pass

        with open(credentials_path, "a+") as f:
            f.write(profile)

    return profile


args = parse_args()

if args.get("config_file"):
    with open(args["config_file"], "r") as f:
        user_config = load(f)
else:
    user_config = {
        "global": {},
        "cognito": {},
        "server": {}
    }

install_dir = args["install_dir"]
credentials = args["credentials"]
del args["install_dir"]
del args["credentials"]

validate_args(args, parser=parser)

config = make_config(user_config, args, install_dir)

exec_path = f"{install_dir}/bin/cognito-auth-server"
copyfile(f"{path.dirname(path.abspath(__file__))}/cognito-auth-server", exec_path)

chmod(exec_path, 0o700)

config_path = f'{install_dir}/{args["name"]}.json'

make_systemd(config, config_path)
make_profile(config)
