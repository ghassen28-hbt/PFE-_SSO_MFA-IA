from __future__ import annotations

import argparse
import json
import sys
from urllib import parse, request


def http_json(method: str, url: str, *, headers=None, data=None):
    req = request.Request(url, data=data, headers=headers or {}, method=method)
    with request.urlopen(req, timeout=30) as response:
        payload = response.read().decode("utf-8")
        if not payload:
            return None
        return json.loads(payload)


def fetch_admin_token(args) -> str:
    token_url = (
        f"{args.server.rstrip('/')}/realms/{args.admin_realm}/protocol/openid-connect/token"
    )
    body = parse.urlencode(
        {
            "grant_type": "password",
            "client_id": args.admin_client_id,
            "username": args.admin_user,
            "password": args.admin_password,
        }
    ).encode("utf-8")
    response = http_json(
        "POST",
        token_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body,
    )
    return response["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def set_configure_totp_not_default(args, token: str) -> dict:
    url = (
        f"{args.server.rstrip('/')}/admin/realms/{args.realm}/authentication/required-actions/"
        "CONFIGURE_TOTP"
    )
    action = http_json("GET", url, headers=auth_headers(token))
    action["defaultAction"] = False
    action["enabled"] = True

    http_json(
        "PUT",
        url,
        headers=auth_headers(token),
        data=json.dumps(action).encode("utf-8"),
    )
    return action


def list_users(args, token: str) -> list[dict]:
    base_url = f"{args.server.rstrip('/')}/admin/realms/{args.realm}/users"
    users: list[dict] = []
    first = 0
    page_size = 100

    while True:
        page_url = f"{base_url}?first={first}&max={page_size}"
        batch = http_json("GET", page_url, headers=auth_headers(token)) or []
        if not batch:
            break
        users.extend(batch)
        if len(batch) < page_size:
            break
        first += page_size

    return users


def clear_required_action_from_users(args, token: str) -> list[str]:
    cleared_users: list[str] = []

    for user in list_users(args, token):
        required_actions = list(user.get("requiredActions") or [])
        if "CONFIGURE_TOTP" not in required_actions:
            continue

        required_actions = [
            action for action in required_actions if action != "CONFIGURE_TOTP"
        ]
        user["requiredActions"] = required_actions

        user_url = (
            f"{args.server.rstrip('/')}/admin/realms/{args.realm}/users/{user['id']}"
        )
        http_json(
            "PUT",
            user_url,
            headers=auth_headers(token),
            data=json.dumps(user).encode("utf-8"),
        )
        cleared_users.append(user.get("username") or user["id"])

    return cleared_users


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Disable forced CONFIGURE_TOTP bootstrap in Keycloak and clear it from users."
        )
    )
    parser.add_argument(
        "--server",
        default="https://starting-deals-yes-sara.trycloudflare.com",
    )
    parser.add_argument("--realm", default="PFE-SSO")
    parser.add_argument("--admin-realm", default="master")
    parser.add_argument("--admin-client-id", default="admin-cli")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password", default="admin")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    token = fetch_admin_token(args)
    action = set_configure_totp_not_default(args, token)
    cleared_users = clear_required_action_from_users(args, token)
    print(
        json.dumps(
            {
                "required_action": action["alias"],
                "defaultAction": action["defaultAction"],
                "cleared_users_count": len(cleared_users),
                "cleared_users": cleared_users,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
