# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import click
from flask import current_app
from flask.cli import with_appcontext

from superset.constants import (
    CHANGE_ME_GLOBAL_ASYNC_QUERIES_JWT_SECRET,
    CHANGE_ME_GUEST_TOKEN_JWT_SECRET,
    CHANGE_ME_SECRET_KEY,
)


@click.command()
@with_appcontext
def check_config() -> None:
    """Validate Superset configuration for production readiness.

    Checks that critical secrets have been changed from their insecure
    defaults. Returns exit code 1 if any issues are found.
    """
    config = current_app.config
    issues: list[str] = []

    secret_key = config.get("SECRET_KEY")
    if not secret_key or secret_key == CHANGE_ME_SECRET_KEY:
        issues.append(
            "SECRET_KEY is insecure (empty or default placeholder). "
            "Set SUPERSET_SECRET_KEY env var or override in superset_config.py. "
            "Generate one with: openssl rand -base64 42"
        )

    if config.get("GUEST_TOKEN_JWT_SECRET") == CHANGE_ME_GUEST_TOKEN_JWT_SECRET:
        issues.append(
            "GUEST_TOKEN_JWT_SECRET uses the default value. "
            "Set a strong random value in superset_config.py."
        )

    if (
        config.get("GLOBAL_ASYNC_QUERIES_JWT_SECRET")
        == CHANGE_ME_GLOBAL_ASYNC_QUERIES_JWT_SECRET
    ):
        issues.append(
            "GLOBAL_ASYNC_QUERIES_JWT_SECRET uses the default value. "
            "Set a strong random value in superset_config.py."
        )

    if issues:
        click.echo(click.style("Configuration issues found:", fg="red", bold=True))
        for issue in issues:
            click.echo(click.style(f"  ✗ {issue}", fg="red"))
        raise SystemExit(1)

    click.echo(click.style("All configuration checks passed.", fg="green"))
