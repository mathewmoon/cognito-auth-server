#!/usr/bin/env python3.8
from os import (
    path,
    R_OK,
    W_OK,
    access,
    chmod,
    chown,
    remove,
    stat,
    environ,
    chdir
)
from socketserver import (
    TCPServer as TCPSocketServer,
    UnixStreamServer,
    BaseRequestHandler
)
from pwd import getpwnam
from stat import S_ISSOCK
from logging import getLogger
from json import dumps
from textwrap import dedent
import socketserver
from socket import timeout
import http.server
from time import time, sleep
from threading import Thread
import signal
from botocore.exceptions import ClientError
from cognitoinator import Session
from cognitoinator.providers import TokenFetcher


logger = getLogger("botocore")
logger.setLevel(environ.get("ERROR_LEVEL", "INFO"))


class SocketRequestMixin:
    def authed_response(self, secret: str) -> str:
        """ Reads data from the client to send either an error or the credentials """

        # Send the secret up front or not at all....
        self.request.settimeout(.5)
        buff = 1024
        error = False

        # If the client doesn't send any data we want to assume
        # they aren't ever going to and treat it as a bad secret
        try:
            msg = self.request.recv(buff).decode().strip()
        except timeout:
            logger.warning(f"Timeout receiving credentials from {self.client} on {self.sock_addr}")
            error = True

        if error or msg != secret:
            res = {"error": "not authorized"}
            logger.warning(f"Access denied (bad credentials) for {self.client} on {self.sock_addr}")
        else:
            logger.info(f"SUCCESS for: {self.client} on {self.sock_addr}")
            if self.__class__ is TokenRequestHandler:
                res = self.session.tokens
            elif self.__class__ is IAMRequestHandler:
                res = self.session.auth_client.profile_credentials

        return res

    def handle_error(self, e):
        msg = dedent(f"""
            {e}
            Client: {self.client}
            Socket: {self.sock_addr}
        """)
        logger.exception(msg)
        return {"error": "Internal Error"}


class IAMRequestHandler(BaseRequestHandler, SocketRequestMixin):
    def handle(self):
        self.sock_addr = self.request.getsockname()
        self.client = self.request.getpeername() or "UNKNOWN CLIENT"

        try:
            if secret := self.config["global"].get("auth_secret"):
                res = self.authed_response(secret)
            else:
                res = self.session.auth_client.profile_credentials
                logger.info(f"SUCCESS for: {self.client} on {self.sock_addr}")
        except Exception as e:
            res = self.handle_error(e)

        self.request.sendall(dumps(res).encode())


class TokenRequestHandler(BaseRequestHandler, SocketRequestMixin):
    def handle(self):
        self.sock_addr = self.request.getsockname()
        self.client = self.request.getpeername() or "UNKNOWN CLIENT"

        try:
            if secret := self.config.get("auth_secret"):
                res = self.authed_response(secret)
            else:
                res = self.session.tokens
        except Exception as e:
            res = self.handle_error(e)

        self.request.sendall(dumps(res).encode())


class HttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            if secret := self.config["global"].get("auth_secret"):
                if not self.auth(secret):
                    return

            if self.credential_type == "iam":
                res = dumps(self.session.auth_client.profile_credentials).encode()
            else:
                res = dumps(self.session.tokens).encode()

        except Exception as e:
            logger.exception(e)
            self.send_response(500)
            self.wfile.write("500 Internal Error".encode())
            return

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers
        self.wfile.write(res)

    def auth(self, secret):
        authed = False

        if self.headers.get("Cognito-Api-Key") != secret:
            self.send_response(401)
            self.wfile.write("401 Not Authorized".encode())
        else:
            authed = True

        return authed


class CognitoServer():
    session: Session = None
    STS: object = None

    def __init__(self, config: dict):
        self.config = config
        self.credential_type = self.config["global"]["credential_type"]

        for k, v in self.config["server"].items():
            setattr(self, k, v)

        for k, v in self.config["global"].items():
            setattr(self, k, v)

    def get_session(self) -> Session:
        if isinstance(self, WebServer):
            # We set this because the WebServer uses a single request handler and
            # needs to differentiate whether to look up tokens or iam credentials
            # from its session attribute
            setattr(HttpRequestHandler, "credential_type", self.credential_type)
            iam_handler = HttpRequestHandler
            token_handler = HttpRequestHandler

        else:
            iam_handler = IAMRequestHandler
            token_handler = TokenRequestHandler

        setattr(iam_handler, "config", self.config)
        setattr(token_handler, "config", self.config)

        if self.credential_type == "tokens":
            self.session = TokenFetcher(
                config=self.config["cognito"],
                server=True
            )
            # This allows us to access the session inside of our request handler
            # and actually get the credentials that we want to return
            setattr(token_handler, "session", self.session)
            self.request_handler = token_handler

        else:
            # We are doing IAM
            self.session = Session(cognito_config=self.config["cognito"])
            setattr(iam_handler, "session", self.session)
            self.request_handler = iam_handler
            self.STS = self.session.client("sts")
            self.threaded_credential_refresher()

        return self.session

    def refresh_expired_credentials(self):
        """
        Force credentials to refresh if expired by calling an AWS endpoint.
        The credentials plugin will automatically check the credentials and refresh if needed
        """
        while True:
            try:
                # get_caller_identity() is perfect because it requires no IAM permissions
                self.STS.get_caller_identity()
            except (Exception, ClientError):
                start_time = time()
                logger.info("Credentials have expired. Refreshing credentials")
                self.session.auth_client.cognito_login()
                logger.info(
                    f"refreshed credentials in {time() - start_time} seconds.")
            sleep(5)

    def threaded_credential_refresher(self):
        """
        Starts a separate thread that will call STS.get_caller_identity() in a loop
        so that our credentials will automatically get refreshed by the session's auth handler
        """
        logger.info("Started credential refresher thread.")
        t = Thread(target=self.refresh_expired_credentials)
        t.daemon = True
        t.start()


class SocketServer(CognitoServer):
    def __init__(self, config: dict):
        super().__init__(config)
        self.server = None
        self.set_signal_handlers()
        self.permissions = int(f"0o{self.permissions}", 8)
        self.get_session()

    def set_signal_handlers(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGURG, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGTSTP, self.shutdown)

    def get_socket_path(self) -> str:
        """Determines if self.socket_path is read/writeable"""
        socket_path = self.socket_path
        socket_dir = path.dirname(socket_path)
        if not (
            path.isdir(socket_dir)
            and access(socket_dir, R_OK)
            and access(socket_dir, W_OK)
        ):
            raise OSError(f"Cannot access path to socket {path.dirname(socket_path)}. Make sure path exists and the current user has R/W access.")

        return socket_path

    def set_socket_permissions(self, socket_file: str):
        """Sets permissions on socket file"""
        if isinstance(self.user, str):
            self.user = getpwnam(self.user).pw_uid

        try:
            chown(socket_file, int(self.user), int(self.group))
            chmod(socket_file, self.permissions)
        except Exception as e:
            raise OSError("Could not set permissions/ownership on socket.") from e

    def shutdown(self, _, __):
        try:
            if self.server is not None:
                self.server.server_close()
            if self.socket_path:
                remove(self.socket_path)
        except Exception as e:
            logger.exception(e)
        exit()

    def start(self):
        """Starts the socket server"""
        socket_path = self.get_socket_path()
        self.socket_path = socket_path
        socket_dir = path.dirname(socket_path)
        chdir(socket_dir)
        socket_file = path.basename(socket_path)
        try:
            if S_ISSOCK(stat(socket_file).st_mode):
                try:
                    remove(socket_file)
                except OSError as e:
                    raise Exception(f"Socket file {socket_file} already exists and an exception was raised when trying to remove it.") from e
        except FileNotFoundError:
            pass

        with UnixStreamServer(socket_file, self.request_handler) as SERVER:
            self.server = SERVER
            SERVER.server_activate()
            self.set_socket_permissions(socket_file)
            SERVER.serve_forever()


class TCPServer(CognitoServer):
    def __init__(self, config: dict, request_handler=None):
        super().__init__(config)

        self.get_session()

    def start(self):
        """Starts the server"""
        with TCPSocketServer(
            (self.host, self.port),
            self.request_handler
        ) as SERVER:
            SERVER.serve_forever()


class WebServer(CognitoServer):
    def __init__(self, config: dict):
        super().__init__(config)
        self.get_session()

    def start(self):
        """Starts the server"""
        with TCPSocketServer(
            (self.host, self.port),
            self.request_handler
        ) as SERVER:
            SERVER.serve_forever()
