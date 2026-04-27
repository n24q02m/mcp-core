"""Read skret AWS SSM Parameter Store namespace into a dict.

Reads ``/<namespace>/*`` recursively (handling NextToken pagination), returns
``{key: value}`` with the namespace prefix stripped from each parameter name.

Auth uses the standard boto3 credential chain (``~/.aws/credentials`` /
environment / IAM role) — no interactive login. Default region matches the
skret deployment in ``ap-southeast-1``.
"""

from __future__ import annotations

from typing import Any

import boto3


def load_namespace(path: str, region: str = "ap-southeast-1") -> dict[str, str]:
    """Load all parameters under ``path``. Returns ``{short_key: value}``."""
    client = boto3.client("ssm", region_name=region)
    out: dict[str, str] = {}
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "Path": path,
            "WithDecryption": True,
            "Recursive": True,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = client.get_parameters_by_path(**kwargs)
        for p in resp["Parameters"]:
            short = p["Name"].rsplit("/", 1)[-1]
            out[short] = p["Value"]
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return out


def load_namespace_required(
    path: str,
    required: list[str],
    optional: list[str] | None = None,
    region: str = "ap-southeast-1",
) -> dict[str, str]:
    """Like :func:`load_namespace` but raise ``KeyError`` if any required key
    is missing. Optional keys are tolerated when absent."""
    data = load_namespace(path, region=region)
    missing = [k for k in required if k not in data]
    if missing:
        raise KeyError(f"Missing required skret keys at {path}: {missing}")
    return data
