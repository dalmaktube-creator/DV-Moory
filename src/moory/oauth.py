"""Small, GitHub-backed OAuth authorization server for MCP clients.

Moory uses GitHub as the user-facing identity provider, but issues its own
short-lived MCP access tokens.  GitHub OAuth access tokens are exchanged and
discarded; they are never used as MCP bearer tokens or written to disk.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RegistrationError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response


class GitHubOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """Persisted MCP OAuth provider that authenticates users with GitHub OAuth.

    This is intentionally narrow: GitHub is the only upstream identity provider,
    scopes are configured by Moory, and all state is bounded and stored as hashes
    where the value is a credential.
    """

    ACCESS_TOKEN_TTL = 3600
    REFRESH_TOKEN_TTL = 30 * 24 * 3600
    AUTHORIZATION_CODE_TTL = 300
    PENDING_TTL = 600
    MAX_CLIENTS = 1000
    MAX_RECORDS = 5000

    def __init__(
        self,
        root: Path,
        issuer_url: str,
        *,
        client_id: str,
        client_secret_path: Path,
        resource_url: str,
        scopes: list[str],
        allowed_users: set[str],
    ) -> None:
        if not issuer_url.startswith("https://"):
            raise ValueError("MOORY_PUBLIC_URL must use HTTPS when OAuth is enabled")
        if not client_id or any(char.isspace() for char in client_id):
            raise ValueError("MOORY_GITHUB_OAUTH_CLIENT_ID is invalid")
        expected_secret_path = (root / "config/github-oauth-client-secret").resolve()
        if client_secret_path.resolve() != expected_secret_path:
            raise ValueError("GitHub OAuth client secret path is not allowlisted")
        self.root = root.resolve()
        self.issuer_url = issuer_url.rstrip("/")
        self.resource_url = resource_url.rstrip("/")
        self.client_id = client_id
        self.client_secret_path = expected_secret_path
        self.scopes = list(dict.fromkeys(scopes))
        self.allowed_users = {user.strip() for user in allowed_users if user.strip()}
        if not self.allowed_users or any(
            not all(char.isalnum() or char == "-" for char in user) for user in self.allowed_users
        ):
            raise ValueError("MOORY_GITHUB_OAUTH_ALLOWED_USERS must contain valid GitHub usernames")
        self.state_path = self.root / "logs/oauth-state.json"
        self.callback_path = "/oauth/github/callback"
        self._lock = threading.RLock()
        self._state = self._load_state()

    def _load_state(self) -> dict[str, dict[str, Any]]:
        if not self.state_path.is_file():
            return {
                "clients": {},
                "pending": {},
                "authorization_codes": {},
                "refresh_tokens": {},
                "access_tokens": {},
            }
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise RuntimeError("OAuth state file is unreadable") from None
        if not isinstance(raw, dict):
            raise RuntimeError("OAuth state file is invalid")
        expected = ("clients", "pending", "authorization_codes", "refresh_tokens", "access_tokens")
        if any(not isinstance(raw.get(key), dict) for key in expected):
            raise RuntimeError("OAuth state file is invalid")
        return {key: dict(raw[key]) for key in expected}

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.{secrets.token_hex(8)}.tmp")
        temporary.write_text(json.dumps(self._state, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.state_path)
        os.chmod(self.state_path, 0o600)

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _prune(self, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        for collection in ("pending", "authorization_codes", "refresh_tokens", "access_tokens"):
            expired = [
                key for key, value in self._state[collection].items()
                if int(value.get("expires_at", 0)) <= now
            ]
            for key in expired:
                self._state[collection].pop(key, None)
        for collection in ("authorization_codes", "refresh_tokens", "access_tokens"):
            while len(self._state[collection]) > self.MAX_RECORDS:
                self._state[collection].pop(next(iter(self._state[collection])))

    @staticmethod
    def _client_json(client: OAuthClientInformationFull) -> dict[str, Any]:
        return client.model_dump(mode="json", exclude_none=True)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._lock:
            raw = self._state["clients"].get(client_id)
            return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.redirect_uris or len(client_info.redirect_uris) > 10:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="At least one and at most ten redirect URIs are required",
            )
        for redirect_uri in client_info.redirect_uris:
            parsed = urllib.parse.urlparse(str(redirect_uri))
            loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
                raise RegistrationError(
                    error="invalid_client_metadata",
                    error_description="OAuth redirect URIs must use HTTPS, except loopback HTTP",
                )
        with self._lock:
            self._prune()
            if len(self._state["clients"]) >= self.MAX_CLIENTS:
                raise RegistrationError(
                    error="invalid_client_metadata",
                    error_description="OAuth client registration limit reached",
                )
            self._state["clients"][client_info.client_id] = self._client_json(client_info)
            self._save_state()

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        requested = params.scopes or self.scopes
        if not set(requested).issubset(set(self.scopes)):
            raise AuthorizeError(error="invalid_scope", error_description="Requested OAuth scope is not allowed")
        if params.resource and params.resource.rstrip("/") != self.resource_url:
            raise AuthorizeError(
                error="invalid_target",
                error_description="OAuth resource does not match this MCP server",
            )

        pending_state = secrets.token_urlsafe(32)
        pending = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "state": params.state,
            "scopes": requested,
            "code_challenge": params.code_challenge,
            "resource": self.resource_url,
            "expires_at": int(time.time()) + self.PENDING_TTL,
        }
        with self._lock:
            self._prune()
            self._state["pending"][pending_state] = pending
            self._save_state()

        query = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": f"{self.issuer_url}{self.callback_path}",
                "scope": "read:user",
                "state": pending_state,
                "allow_signup": "false",
            }
        )
        return f"https://github.com/login/oauth/authorize?{query}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        with self._lock:
            raw = self._state["authorization_codes"].get(self._digest(authorization_code))
            if not raw or raw.get("client_id") != client.client_id:
                return None
            return AuthorizationCode.model_validate({**raw, "code": authorization_code})

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        now = int(time.time())
        access_expires = now + self.ACCESS_TOKEN_TTL
        refresh_expires = now + self.REFRESH_TOKEN_TTL
        with self._lock:
            self._prune(now)
            code_key = self._digest(authorization_code.code)
            if code_key not in self._state["authorization_codes"]:
                raise TokenError(error="invalid_grant", error_description="authorization code was already used")
            self._state["authorization_codes"].pop(code_key, None)
            self._state["access_tokens"][self._digest(access)] = {
                "client_id": client.client_id,
                "scopes": authorization_code.scopes,
                "expires_at": access_expires,
                "resource": authorization_code.resource or self.resource_url,
                "subject": authorization_code.subject,
            }
            self._state["refresh_tokens"][self._digest(refresh)] = {
                "client_id": client.client_id,
                "scopes": authorization_code.scopes,
                "expires_at": refresh_expires,
                "subject": authorization_code.subject,
            }
            self._save_state()
        return OAuthToken(
            access_token=access,
            expires_in=self.ACCESS_TOKEN_TTL,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        with self._lock:
            raw = self._state["refresh_tokens"].get(self._digest(refresh_token))
            if not raw or raw.get("client_id") != client.client_id:
                return None
            return RefreshToken.model_validate({**raw, "token": refresh_token})

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        access = secrets.token_urlsafe(48)
        rotated_refresh = secrets.token_urlsafe(48)
        now = int(time.time())
        with self._lock:
            self._prune(now)
            refresh_key = self._digest(refresh_token.token)
            if refresh_key not in self._state["refresh_tokens"]:
                raise TokenError(error="invalid_grant", error_description="refresh token was already used")
            self._state["refresh_tokens"].pop(refresh_key, None)
            self._state["access_tokens"][self._digest(access)] = {
                "client_id": client.client_id,
                "scopes": scopes,
                "expires_at": now + self.ACCESS_TOKEN_TTL,
                "resource": self.resource_url,
                "subject": refresh_token.subject,
            }
            self._state["refresh_tokens"][self._digest(rotated_refresh)] = {
                "client_id": client.client_id,
                "scopes": scopes,
                "expires_at": now + self.REFRESH_TOKEN_TTL,
                "subject": refresh_token.subject,
            }
            self._save_state()
        return OAuthToken(
            access_token=access,
            expires_in=self.ACCESS_TOKEN_TTL,
            scope=" ".join(scopes),
            refresh_token=rotated_refresh,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        with self._lock:
            raw = self._state["access_tokens"].get(self._digest(token))
            if not raw or int(raw.get("expires_at", 0)) <= int(time.time()):
                return None
            return AccessToken.model_validate({**raw, "token": token})

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        with self._lock:
            self._state["access_tokens"].pop(self._digest(token.token), None)
            self._state["refresh_tokens"].pop(self._digest(token.token), None)
            self._save_state()

    def _github_request(self, url: str, *, data: dict[str, str] | None = None) -> dict[str, Any]:
        secret = self.client_secret_path.read_text(encoding="utf-8").strip()
        if len(secret) < 20 or any(char.isspace() for char in secret):
            raise RuntimeError("GitHub OAuth client secret is invalid")
        payload = None if data is None else urllib.parse.urlencode(data).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            method="POST" if payload is not None else "GET",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Moory-OAuth/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                parsed = json.loads(response.read(200_000).decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as error:
            raise RuntimeError("GitHub OAuth request failed") from error
        if not isinstance(parsed, dict):
            raise RuntimeError("GitHub OAuth returned an invalid response")
        return parsed

    def _exchange_github_code(self, code: str) -> str:
        result = self._github_request(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret_path.read_text(encoding="utf-8").strip(),
                "code": code,
            },
        )
        token = str(result.get("access_token", ""))
        if not token or result.get("token_type") != "bearer":
            raise RuntimeError("GitHub OAuth did not return a bearer token")
        return token

    @staticmethod
    def _github_identity(token: str) -> str:
        request = urllib.request.Request(
            "https://api.github.com/user",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "Moory-OAuth/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                user = json.loads(response.read(200_000).decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as error:
            raise RuntimeError("GitHub identity lookup failed") from error
        login = str(user.get("login", "")) if isinstance(user, dict) else ""
        if not login or len(login) > 39:
            raise RuntimeError("GitHub identity response is invalid")
        return login

    def _finish_authorization(self, pending: dict[str, Any], subject: str) -> str:
        code = secrets.token_urlsafe(48)
        record = {
            "scopes": pending["scopes"],
            "expires_at": int(time.time()) + self.AUTHORIZATION_CODE_TTL,
            "client_id": pending["client_id"],
            "code_challenge": pending["code_challenge"],
            "redirect_uri": pending["redirect_uri"],
            "redirect_uri_provided_explicitly": pending["redirect_uri_provided_explicitly"],
            "resource": pending["resource"],
            "subject": subject,
        }
        with self._lock:
            self._state["authorization_codes"][self._digest(code)] = record
            self._save_state()
        params: dict[str, str] = {"code": code}
        if pending.get("state") is not None:
            params["state"] = str(pending["state"])
        params["iss"] = self.issuer_url
        redirect = urllib.parse.urlsplit(str(pending["redirect_uri"]))
        existing = urllib.parse.parse_qsl(redirect.query, keep_blank_values=True)
        location = redirect._replace(
            query=urllib.parse.urlencode(existing + list(params.items()))
        )
        return urllib.parse.urlunsplit(location)

    async def github_callback(self, request: Request) -> Response:
        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        error = request.query_params.get("error")
        with self._lock:
            pending = self._state["pending"].pop(state, None) if state else None
            self._save_state()
        if not pending or int(pending.get("expires_at", 0)) <= int(time.time()):
            return HTMLResponse("OAuth state is invalid or expired.", status_code=400)
        if error or not code:
            error_params = {"error": "access_denied"}
            if pending.get("state") is not None:
                error_params["state"] = str(pending["state"])
            redirect = urllib.parse.urlsplit(str(pending["redirect_uri"]))
            existing = urllib.parse.parse_qsl(redirect.query, keep_blank_values=True)
            target = urllib.parse.urlunsplit(
                redirect._replace(query=urllib.parse.urlencode(existing + list(error_params.items())))
            )
            return RedirectResponse(target, status_code=302)
        try:
            github_token = await asyncio.to_thread(self._exchange_github_code, code)
            subject = await asyncio.to_thread(self._github_identity, github_token)
            if subject not in self.allowed_users:
                return HTMLResponse("This GitHub account is not allowed to use Moory.", status_code=403)
            target = self._finish_authorization(pending, subject)
        except RuntimeError:
            return HTMLResponse("GitHub authorization failed. Please try again.", status_code=502)
        return RedirectResponse(target, status_code=302)

    async def login_landing(self, request: Request) -> Response:
        return HTMLResponse(
            "<!doctype html><title>Moory authorization</title>"
            "<p>Moory authorization is handled securely by GitHub. "
            "Continue the sign-in flow from the ChatGPT window.</p>",
            headers={"Cache-Control": "no-store"},
        )