from __future__ import annotations

import argparse
import json
import subprocess
import sys


def run_kcadm(args: list[str], *, container: str, credentials: list[str]) -> str:
    command = [
        "docker.exe",
        "exec",
        container,
        "/opt/keycloak/bin/kcadm.sh",
        *args,
        *credentials,
    ]
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def get_json(args: list[str], *, container: str, credentials: list[str]):
    raw = run_kcadm(args, container=container, credentials=credentials)
    json_start = raw.find("[")
    if json_start < 0:
        json_start = raw.find("{")
    if json_start < 0:
        raise ValueError(f"kcadm did not return JSON: {raw}")
    return json.loads(raw[json_start:])


def ensure_flow(args) -> str:
    credentials = [
        "--server",
        args.server,
        "--realm",
        "master",
        "--user",
        args.admin_user,
        "--password",
        args.admin_password,
    ]

    flows = get_json(
        ["get", "authentication/flows", "-r", args.realm],
        container=args.container,
        credentials=credentials,
    )
    flow = next((item for item in flows if item.get("alias") == args.flow_alias), None)

    if not flow:
        run_kcadm(
            [
                "create",
                "authentication/flows",
                "-r",
                args.realm,
                "-s",
                f"alias={args.flow_alias}",
                "-s",
                "providerId=basic-flow",
                "-s",
                "topLevel=true",
                "-s",
                "builtIn=false",
                "-s",
                "description=Step-up flow: existing SSO session plus OTP required",
            ],
            container=args.container,
            credentials=credentials,
        )
        flows = get_json(
            ["get", "authentication/flows", "-r", args.realm],
            container=args.container,
            credentials=credentials,
        )
        flow = next((item for item in flows if item.get("alias") == args.flow_alias), None)

    if not flow:
        raise RuntimeError(f"Unable to create or find flow {args.flow_alias}")

    executions = get_json(
        ["get", f"authentication/flows/{args.flow_alias}/executions", "-r", args.realm],
        container=args.container,
        credentials=credentials,
    )

    providers = {item.get("providerId"): item for item in executions}
    for provider in ["auth-cookie", "auth-otp-form"]:
        if provider not in providers:
            run_kcadm(
                [
                    "create",
                    f"authentication/flows/{args.flow_alias}/executions/execution",
                    "-r",
                    args.realm,
                    "-s",
                    f"provider={provider}",
                ],
                container=args.container,
                credentials=credentials,
            )

    executions = get_json(
        ["get", f"authentication/flows/{args.flow_alias}/executions", "-r", args.realm],
        container=args.container,
        credentials=credentials,
    )
    for execution in executions:
        if execution.get("providerId") not in {"auth-cookie", "auth-otp-form"}:
            continue
        if execution.get("requirement") == "REQUIRED":
            continue
        run_kcadm(
            [
                "update",
                f"authentication/flows/{args.flow_alias}/executions",
                "-r",
                args.realm,
                "-n",
                "-s",
                f"id={execution['id']}",
                "-s",
                "requirement=REQUIRED",
            ],
            container=args.container,
            credentials=credentials,
        )

    clients = get_json(
        ["get", "clients", "-r", args.realm, "-q", f"clientId={args.client_id}"],
        container=args.container,
        credentials=credentials,
    )
    if not clients:
        raise RuntimeError(f"Client not found: {args.client_id}")

    client_id = clients[0]["id"]
    run_kcadm(
        [
            "update",
            f"clients/{client_id}",
            "-r",
            args.realm,
            "-s",
            f"authenticationFlowBindingOverrides.browser={flow['id']}",
        ],
        container=args.container,
        credentials=credentials,
    )

    return flow["id"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Configure Keycloak step-up client to require SSO cookie + OTP."
    )
    parser.add_argument("--container", default="pfe_keycloak")
    parser.add_argument("--server", default="http://localhost:8080")
    parser.add_argument("--realm", default="PFE-SSO")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password", default="admin")
    parser.add_argument("--client-id", default="portal-stepup-totp-client")
    parser.add_argument("--flow-alias", default="browser-stepup-totp-cookie-pfe")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    flow_id = ensure_flow(args)
    print(
        f"Configured {args.client_id} to use browser flow "
        f"{args.flow_alias} ({flow_id})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
