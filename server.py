"""A minimal MCP server exposing sandboxed local file/data tools over Streamable HTTP.

Config via environment variables (all optional):
  MCP_ROOT              Directory all file access is confined to. Default: ./data
  MCP_HOST              Bind address. Default: 127.0.0.1
  MCP_PORT              Port. Default: 8000
  MCP_AUTH_TOKEN        Static shared-secret bearer auth (local/dev only). Ignored
                        if GitHub OAuth is configured (see below) -- OAuth wins.
  MCP_DB_PATH           SQLite file for OAuth client/token storage. Default: ./data/mcp.db

  GitHub OAuth (for remote use, e.g. adding this server as a Claude.ai connector).
  Set all four of these to enable -- otherwise the server runs with no OAuth at all:
  GITHUB_CLIENT_ID      Client ID of a GitHub OAuth App.
  GITHUB_CLIENT_SECRET  Client secret of that GitHub OAuth App.
  MCP_ISSUER_URL        Public URL of this server, e.g. https://my-app.fly.dev
  MCP_RESOURCE_SERVER_URL  Same as MCP_ISSUER_URL in this single-server setup.

Local debug:   uv run mcp dev server.py
Run server:    uv run server.py
"""

import logging
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# --- Configuration -----------------------------------------------------------
ROOT = Path(os.environ.get("MCP_ROOT", "./data")).resolve()
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))
AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN")  # None => no static-token auth

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
ISSUER_URL = os.environ.get("MCP_ISSUER_URL")
RESOURCE_SERVER_URL = os.environ.get("MCP_RESOURCE_SERVER_URL")
DB_PATH = Path(os.environ.get("MCP_DB_PATH", "./data/mcp.db")).resolve()

OAUTH_ENABLED = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET and ISSUER_URL and RESOURCE_SERVER_URL)

ROOT.mkdir(parents=True, exist_ok=True)

if OAUTH_ENABLED and AUTH_TOKEN:
    logging.warning("Both GitHub OAuth and MCP_AUTH_TOKEN are configured; OAuth takes precedence.")

if OAUTH_ENABLED:
    from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions

    import oauth_store
    from github_oauth import GitHubOAuthProvider, complete_github_login

    _db_conn = oauth_store.init_db(DB_PATH)
    _callback_url = f"{RESOURCE_SERVER_URL.rstrip('/')}/auth/github/callback"
    _oauth_provider = GitHubOAuthProvider(
        _db_conn,
        github_client_id=GITHUB_CLIENT_ID,
        github_client_secret=GITHUB_CLIENT_SECRET,
        callback_url=_callback_url,
    )
    _auth_settings = AuthSettings(
        issuer_url=ISSUER_URL,
        resource_server_url=RESOURCE_SERVER_URL,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["files"],
            default_scopes=["files"],
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    mcp = FastMCP(
        "files-server",
        host=HOST,
        port=PORT,
        auth_server_provider=_oauth_provider,
        auth=_auth_settings,
    )
else:
    mcp = FastMCP("files-server", host=HOST, port=PORT)


def _safe(path: str) -> Path:
    """Resolve `path` under ROOT, rejecting anything that escapes it."""
    p = (ROOT / path).resolve()
    if p != ROOT and ROOT not in p.parents:
        raise ValueError("Path escapes the allowed root")
    return p


# --- Tools -------------------------------------------------------------------
@mcp.tool()
def list_files(subdir: str = ".") -> list[str]:
    """List all files (recursively) under a subdirectory of the root."""
    base = _safe(subdir)
    return sorted(str(p.relative_to(ROOT)) for p in base.rglob("*") if p.is_file())


@mcp.tool()
def read_file(path: str) -> str:
    """Read a UTF-8 text file located under the root."""
    return _safe(path).read_text(encoding="utf-8")


@mcp.tool()
def search_files(query: str, subdir: str = ".") -> list[str]:
    """Return paths of text files under `subdir` whose contents contain `query`
    (case-insensitive)."""
    needle = query.lower()
    hits: list[str] = []
    for p in _safe(subdir).rglob("*"):
        if p.is_file():
            try:
                if needle in p.read_text(encoding="utf-8", errors="ignore").lower():
                    hits.append(str(p.relative_to(ROOT)))
            except Exception:
                pass  # skip unreadable/binary files
    return sorted(hits)


# --- Resource: load file contents by URI (file://<path>) ---------------------
@mcp.resource("file://{path}")
def file_resource(path: str) -> str:
    return _safe(path).read_text(encoding="utf-8")


# --- GitHub OAuth callback: completes the delegated login round-trip --------
if OAUTH_ENABLED:
    from mcp.server.auth.provider import AuthorizeError
    from starlette.requests import Request
    from starlette.responses import JSONResponse, RedirectResponse, Response

    @mcp.custom_route("/auth/github/callback", methods=["GET"])
    async def github_callback(request: Request) -> Response:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return JSONResponse({"error": "invalid_request", "error_description": "missing code or state"}, status_code=400)

        try:
            redirect_url = await complete_github_login(
                _db_conn,
                code=code,
                state=state,
                github_client_id=GITHUB_CLIENT_ID,
                github_client_secret=GITHUB_CLIENT_SECRET,
                callback_url=_callback_url,
            )
        except AuthorizeError as e:
            return JSONResponse({"error": e.error, "error_description": e.error_description}, status_code=400)

        return RedirectResponse(redirect_url, status_code=302)


# --- Optional static-token auth for remote use (local/dev fallback) ---------
def _build_app():
    """Return the Streamable HTTP ASGI app. If OAuth is enabled, the app is
    already fully wired by the FastMCP constructor. Otherwise, wrap with
    static bearer auth if MCP_AUTH_TOKEN is configured."""
    app = mcp.streamable_http_app()
    if OAUTH_ENABLED or not AUTH_TOKEN:
        return app

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    class BearerAuth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            header = request.headers.get("authorization", "")
            if header != f"Bearer {AUTH_TOKEN}":
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await call_next(request)

    app.add_middleware(BearerAuth)
    return app


if __name__ == "__main__":
    if AUTH_TOKEN or OAUTH_ENABLED:
        # Auth enabled -> run the wrapped ASGI app via uvicorn.
        import uvicorn

        uvicorn.run(_build_app(), host=HOST, port=PORT)
    else:
        # No auth (local) -> use the SDK runner directly.
        mcp.run(transport="streamable-http")
