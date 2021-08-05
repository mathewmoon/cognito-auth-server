BASE_TEMPLATE = r"""
[Unit]
Description=Runs the Cognito Auth Server
After=network-online.target

[Service]
User={user}
Group={group}
TimeoutStartSec=120
Restart=on-failure
RestartSec=20
WorkingDirectory=/opt/cognito_auth_server
ExecStart=/bin/bash -c "cognito-auth-server \
    -c {config_path} \
    -r 0 " 2>&1 | tee -a {log_path}

[Install]
WantedBy=multi-user.target
"""
