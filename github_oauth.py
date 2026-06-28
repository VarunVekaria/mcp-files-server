"""OAuthAuthorizationServerProvider that delegates identity to GitHub.

Our server is the Authorization Server from Claude's (or any MCP client's)
point of view, but `authorize()` bounces the human through GitHub for the
actual identity check, then mints our own short-lived codes/tokens. See
`mcp.server.auth.provider.OAuthAuthorizationServerProvider.authorize`'s
docstring for the AS-delegates-to-3rd-party diagram this implements.
"""

import secrets
import sqlite3
import time

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

import oauth_store

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_SCOPE = "read:user"

ACCESS_TOKEN_TTL_SECONDS = 3600
AUTH_CODE_TTL_SECONDS = 300


class GitHubOAuthProvider:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        github_client_id: str,
        github_client_secret: str,
        callback_url: str,
    ) -> None:
        self.conn = conn
        self.github_client_id = github_client_id
        self.github_client_secret = github_client_secret
        self.callback_url = callback_url

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return oauth_store.get_client(self.conn, client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        oauth_store.save_client(self.conn, client_info)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        our_state = secrets.token_urlsafe(32)
        oauth_store.save_pending_github(
            self.conn,
            our_state,
            {
                "client_id": client.client_id,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "state": params.state,
                "code_challenge": params.code_challenge,
                "scopes": params.scopes,
                "resource": params.resource,
            },
        )
        return construct_redirect_uri(
            GITHUB_AUTHORIZE_URL,
            client_id=self.github_client_id,
            redirect_uri=self.callback_url,
            state=our_state,
            scope=GITHUB_SCOPE,
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = oauth_store.get_auth_code(self.conn, authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        oauth_store.delete_auth_code(self.conn, authorization_code.code)

        access_token = AccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + ACCESS_TOKEN_TTL_SECONDS,
            resource=authorization_code.resource,
            subject=authorization_code.subject,
        )
        refresh_token = RefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            subject=authorization_code.subject,
        )
        oauth_store.save_access_token(self.conn, access_token)
        oauth_store.save_refresh_token(self.conn, refresh_token)

        return OAuthToken(
            access_token=access_token.token,
            refresh_token=refresh_token.token,
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        token = oauth_store.get_refresh_token(self.conn, refresh_token)
        if token is None or token.client_id != client.client_id:
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        oauth_store.delete_refresh_token(self.conn, refresh_token.token)

        new_scopes = scopes or refresh_token.scopes
        new_access_token = AccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=new_scopes,
            expires_at=int(time.time()) + ACCESS_TOKEN_TTL_SECONDS,
            subject=refresh_token.subject,
        )
        new_refresh_token = RefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=new_scopes,
            subject=refresh_token.subject,
        )
        oauth_store.save_access_token(self.conn, new_access_token)
        oauth_store.save_refresh_token(self.conn, new_refresh_token)

        return OAuthToken(
            access_token=new_access_token.token,
            refresh_token=new_refresh_token.token,
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=" ".join(new_scopes) if new_scopes else None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        return oauth_store.get_access_token(self.conn, token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            oauth_store.delete_access_token(self.conn, token.token)
        else:
            oauth_store.delete_refresh_token(self.conn, token.token)


async def complete_github_login(
    conn: sqlite3.Connection,
    *,
    code: str,
    state: str,
    github_client_id: str,
    github_client_secret: str,
    callback_url: str,
) -> str:
    """Exchange GitHub's `code` for an identity, then redirect back to the
    original MCP client with our own authorization code."""
    pending = oauth_store.pop_pending_github(conn, state)
    if pending is None:
        raise AuthorizeError(error="access_denied", error_description="GitHub login session expired or invalid")

    async with httpx.AsyncClient() as http:
        token_resp = await http.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": github_client_id,
                "client_secret": github_client_secret,
                "code": code,
                "redirect_uri": callback_url,
            },
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        github_token = token_resp.json().get("access_token")
        if not github_token:
            raise AuthorizeError(error="access_denied", error_description="GitHub did not return an access token")

        user_resp = await http.get(
            GITHUB_USER_URL,
            headers={"Authorization": f"Bearer {github_token}", "Accept": "application/json"},
        )
        user_resp.raise_for_status()
        github_user = user_resp.json()

    subject = f"github:{github_user['id']}"

    our_code = secrets.token_urlsafe(32)
    auth_code = AuthorizationCode(
        code=our_code,
        scopes=pending["scopes"] or [],
        expires_at=time.time() + AUTH_CODE_TTL_SECONDS,
        client_id=pending["client_id"],
        code_challenge=pending["code_challenge"],
        redirect_uri=pending["redirect_uri"],
        redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
        resource=pending["resource"],
        subject=subject,
    )
    oauth_store.save_auth_code(conn, auth_code)

    return construct_redirect_uri(pending["redirect_uri"], code=our_code, state=pending["state"])
