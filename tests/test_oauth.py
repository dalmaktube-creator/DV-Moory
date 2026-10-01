import asyncio
import json
import tempfile
import urllib.parse
from pathlib import Path

from mcp.shared.auth import OAuthClientInformationFull

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from moory.oauth import GitHubOAuthProvider


async def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "config").mkdir()
        (root / "logs").mkdir()
        secret_path = root / "config/github-oauth-client-secret"
        secret_path.write_text("s" * 40, encoding="utf-8")
        provider = GitHubOAuthProvider(
            root,
            "https://mcp.example.test",
            client_id="Iv1.1234567890",
            client_secret_path=secret_path,
            resource_url="https://mcp.example.test/mcp",
            scopes=["moory"],
            allowed_users={"github-user"},
        )
        client = OAuthClientInformationFull(
            client_id="chatgpt-test",
            client_secret=None,
            token_endpoint_auth_method="none",
            redirect_uris=["https://chatgpt.example.test/callback"],
            response_types=["code"],
            grant_types=["authorization_code", "refresh_token"],
            scope="moory",
        )
        await provider.register_client(client)
        assert await provider.get_client(client.client_id)
        pending_redirect = await provider.authorize(
            client,
            type(
                "Params",
                (),
                {
                    "scopes": ["moory"],
                    "resource": "https://mcp.example.test/mcp",
                    "code_challenge": "challenge",
                    "redirect_uri": "https://chatgpt.example.test/callback",
                    "redirect_uri_provided_explicitly": True,
                    "state": "chatgpt-state",
                },
            )(),
        )
        pending_query = urllib.parse.parse_qs(urllib.parse.urlsplit(pending_redirect).query)
        assert pending_query["client_id"] == ["Iv1.1234567890"]
        assert json.loads((root / "logs/oauth-state.json").read_text())["pending"]

        with provider._lock:
            pending_state = pending_query["state"][0]
            pending = provider._state["pending"].pop(pending_state)
        callback_target = provider._finish_authorization(pending, "github-user")
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(callback_target).query)["code"][0]
        persisted = json.loads((root / "logs/oauth-state.json").read_text())
        assert code not in json.dumps(persisted)
        authorization_code = await provider.load_authorization_code(client, code)
        assert authorization_code and authorization_code.subject == "github-user"
        token = await provider.exchange_authorization_code(client, authorization_code)
        persisted = json.loads((root / "logs/oauth-state.json").read_text())
        assert token.access_token not in json.dumps(persisted)
        assert (token.refresh_token or "") not in json.dumps(persisted)
        access = await provider.load_access_token(token.access_token)
        assert access and access.subject == "github-user" and access.resource.endswith("/mcp")
        assert await provider.load_authorization_code(client, code) is None
        refreshed = await provider.load_refresh_token(client, token.refresh_token or "")
        assert refreshed
        rotated = await provider.exchange_refresh_token(client, refreshed, ["moory"])
        assert rotated.access_token != token.access_token


asyncio.run(main())
print("OAuth provider checks passed")