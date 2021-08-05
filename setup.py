#!/usr/bin/env python3.8
import io
from setuptools import setup


setup(
    name="cognito-auth-server",
    version="0.0.1",
    description="Provides a server that can act as a TCP, HTTP, or Unix Domain Socket server to provide IAM Credentials from a Cognito assumed role or Cognito Session tokens",
    author="Mathew Moon",
    author_email="mmoon@quinovas.com",
    url="https://github.com/QuiNovas/cognito_auth_server",
    license="Apache 2.0",
    long_description=io.open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=["cognito_auth_server"],
    package_dir={"cognito_auth_server": "src/cognito_auth_server"},
    install_requires=["cognitoinator"],
    scripts=["src/cognito_auth_server/scripts/cognito-auth-server", "src/cognito_auth_server/scripts/install-cognito-server"],
    include_package_data=True,
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
    ]
)
