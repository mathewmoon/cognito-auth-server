import argparse


parser = argparse.ArgumentParser()


def parse_args():
    parser.add_argument(
        "-s",
        "--server-type",
        choices={"unix", "tcp", "http"},
        default="unix",
        help="The type of server to run (unix, tcp, or http)."
    )

    parser.add_argument(
        "-C",
        "--credential-type",
        choices={"tokens", "iam"},
        default="iam",
        help="Whether we are fetching IAM credentials or Cognito tokens."
    )

    parser.add_argument(
        "-p",
        "--cognito-profile",
        type=str,
        default=None,
        help="The name of the cognito profile to source for creating a session."
    )

    parser.add_argument(
        "-f",
        "--cognito-credentials-file",
        type=str,
        default=None,
        help="An optional non-standard path to a credentials file. Defaults to ~/.aws/cognito_credentials"
    )

    parser.add_argument(
        "-c",
        "--config-file",
        type=str,
        default=None
    )

    parser.add_argument(
        "-P",
        "--port",
        type=int,
        default=None,
        help="Port to bind to."
    )

    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default=None,
        help="The hostname or address to bind to."
    )

    parser.add_argument(
        "-u",
        "--user",
        type=int,
        default=None,
        help="User who should own the Unix socket. Must be an integer (uid)."
    )

    parser.add_argument(
        "-g",
        "--group",
        type=int,
        default=None,
        help="Group applied to the Unix socket. Must be an integer (gid)"
    )

    parser.add_argument(
        "--permissions",
        type=int,
        default=None,
        help="Unix file permissions to apply to the Unix socket."
    )

    parser.add_argument(
        "-S",
        "--socket-path",
        type=str,
        default=None,
        help="Path to apply to the Unix socket."
    )

    parser.add_argument(
        "-n",
        "--server_name",
        type=str,
        default="cognitod",
        help="The name of the systemd service"
    )

    parser.add_argument(
        "-i",
        "--install-dir",
        type=str,
        default="/opt/cognito_auth_server",
        help="Location to install cognito server."
    )

    parser.add_argument(
        "-e",
        "--use-env",
        action="store_true",
        help="Whether or not to use env variables"
    )

    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=5,
        help="Max number of times to retry starting the server before raising an exception."
    )

    parser.add_argument(
        "-a",
        "--auth_secret",
        type=str,
        default=None,
        help="Secret to use for server authentication"
    )
    args = parser.parse_args()

    return vars(args)
