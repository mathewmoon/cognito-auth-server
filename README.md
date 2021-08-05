Run an auth server that provides AWS credentials via Unix sockets, tcp, or http from a Cognito user
===================================================================================================

Overview
========
This package provides the tools for running an auth server that can  provide AWS credientials via Cognito. Using this we can provide Cognito tokens
or IAM credentials over Unix domain sockets, tcp, or http, with an optional required secret. The easiest way to get started is to install the package
and run cognito-auth-config-builder. It will launch an interactive shell that will generate a config and optionally generate a systemd file for running
the auth server as a service. Another way to run the server is to configure environment variables as per the cognitoinator package, which the auth
server uses under the hood. Configuration documentation can be found here https://pypi.org/project/cognitoinator/ . Some info about configuring
env vars is located below.


Configuration
=============

### Env vars

These will take affect before any other credential provider, including
the standard env provider that looks for AWS\_SECRET\_ACCESS\_KEY and
AWS\_ACCESS\_KEY\_ID. If one or more of the following non-optional
variables are found in environ then we will automatically go to env
based credential mapping

-   COGNITO_USERNAME
-   COGNITO_PASSWORD
-   COGNITO_USER_POOL_ID
-   COGNITO_IDENTITY_POOL_ID
-   COGNITO_APP_ID
-   COGNITO_METADATA (Deserialized and passed as ClientMetadata in
    boto3.client("cognito-idp").initiate_auth()) - Optional
-   AWS_ROLE_ARN - Optional



Usage
=====

    >cognito-auth-server -h

    usage: cognito-auth-server [-h] [-s {http,unix,tcp}] [-C {iam,tokens}] [-p COGNITO_PROFILE] [-f COGNITO_CREDENTIALS_FILE] [-c CONFIG_FILE] [-P PORT] [-H HOST] [-u USER] [-g GROUP] [--permissions PERMISSIONS] [-S SOCKET_PATH] [-n SERVER_NAME] [-i INSTALL_DIR] [-e]
                            [-r RETRIES] [-a AUTH_SECRET]

    optional arguments:
    -h, --help            show this help message and exit
    -s {http,unix,tcp}, --server-type {http,unix,tcp}
                            The type of server to run (unix, tcp, or http).
    -C {iam,tokens}, --credential-type {iam,tokens}
                            Whether we are fetching IAM credentials or Cognito tokens.
    -p COGNITO_PROFILE, --cognito-profile COGNITO_PROFILE
                            The name of the cognito profile to source for creating a session.
    -f COGNITO_CREDENTIALS_FILE, --cognito-credentials-file COGNITO_CREDENTIALS_FILE
                            An optional non-standard path to a credentials file. Defaults to ~/.aws/cognito_credentials
    -c CONFIG_FILE, --config-file CONFIG_FILE
    -P PORT, --port PORT  Port to bind to.
    -H HOST, --host HOST  The hostname or address to bind to.
    -u USER, --user USER  User who should own the Unix socket. Must be an integer (uid).
    -g GROUP, --group GROUP
                            Group applied to the Unix socket. Must be an integer (gid)
    --permissions PERMISSIONS
                            Unix file permissions to apply to the Unix socket.
    -S SOCKET_PATH, --socket-path SOCKET_PATH
                            Path to apply to the Unix socket.
    -n SERVER_NAME, --server_name SERVER_NAME
                            The name of the systemd service
    -i INSTALL_DIR, --install-dir INSTALL_DIR
                            Location to install cognito server.
    -e, --use-env         Whether or not to use env variables
    -r RETRIES, --retries RETRIES
                            Max number of times to retry starting the server before raising an exception.
    -a AUTH_SECRET, --auth_secret AUTH_SECRET
                            Secret to use for server authentication


### Using env config
.. code-block:: shell

    > source my_cognito_vars.env
    > cognito-auth-server -s tcp -e


### Using ~/.aws/cognito_profile

    > cognito-auth-server -s tcp -p my_cognito_profile


### Using a config file

    > cognito-auth-server -s tcp -c /path/to/config.json

### Using a secret

    > cognito-auth-server -s http -e -a superubersecret


Example config
==============

    {
        "global": {
            "user": 501,
            "group": 20,
            "server_type": "tcp",
            "credential_type": "iam",
            "service_name": "cognitod",
            "auth_secret": mysupermadeupsecret
        },
        "cognito": {
            "username": "foo@bar.com",
            "password": "ubersecurepwd",
            "app_id": "abcdef123456",
            "user_pool_id": "us-east-1_1a2b3c4b",
            "identity_pool_id": "us-east-1:bbbb-aaaa-3333-111-222222222",
            "region": "us-east-1",
            "auth_type": "user_srp"
        },
        "server": {
            "port": 5500,
            "host": "127.0.0.1"
        }
    }


Getting credentials
===================

### From tcp

    > nc localhost 5500

### From tcp using a secret

    > nc localhost 5500 <<< mysuperdupermadeupsecret

### From unix domain socket

    > nc -U /path/to/socket.sock

### From unix using a secret

    > nc -U /path/to/socket.sock <<< mysuperdupermadeupsecret

### From tcp

    > curl http://localhost:8080

### From tcp using secret

    > curl -H "Cognito-Api-Key: mysuperdupermadeupsecret" http://localhost:8080


The commands for Unix domain and TCP may differ slightly between OS's depending on what version of netcat you have installed


Using the server as the default AWS credential provider
=======================================================

Once you have the server running you can use these credentials with any application that uses your AWS credentials or config file. Just update
your profile to use your server as the credential_process. An example of ~/.aws/credentials


    [cognito_server]
    credential_process: sh -c "nc localhost 5500"


And now this profile will automatically use the server. You can test this by running an aws cli command such as:

    > aws --profile cognito_server s3 ls


