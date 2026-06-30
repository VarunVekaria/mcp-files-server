"""A minimal MCP server exposing sandboxed local file/data tools over HTTP.

Config via environment variables (all optional):
  MCP_ROOT                    Directory all file access is confined to. Default: ./data
  MCP_HOST                    Bind address. Default: 127.0.0.1
  MCP_PORT                    Port. Default: 8000

  GitHub OAuth (for remote use, e.g. adding this server as a Claude.ai/Claude
  Desktop connector). Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and
  MCP_BASE_URL to enable -- otherwise the server runs locally with no auth.
  GITHUB_CLIENT_ID            Client ID of a GitHub OAuth App.
  GITHUB_CLIENT_SECRET        Client secret of that GitHub OAuth App.
  MCP_BASE_URL                Public URL of this server, e.g. https://my-app.fly.dev
  MCP_JWT_SIGNING_KEY         Fixed key for signing issued tokens. Without this,
                              a random key is generated per process, invalidating
                              every session on restart -- set this for any
                              deployment that's expected to restart.
  MCP_STORAGE_ENCRYPTION_KEY  Fernet key encrypting OAuth client/token storage at
                              rest. Generate with:
                              python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

  OpenTelemetry tracing is native to FastMCP and configured entirely outside
  this file -- run via `opentelemetry-instrument` (see Dockerfile) pointed at
  an OTLP endpoint, e.g. Grafana Cloud.

Local debug:   uv run fastmcp dev server.py
Run server:    uv run server.py
"""

import os
from pathlib import Path

from fastmcp import FastMCP

# --- Configuration -----------------------------------------------------------
ROOT = Path(os.environ.get("MCP_ROOT", "./data")).resolve()
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
BASE_URL = os.environ.get("MCP_BASE_URL")
JWT_SIGNING_KEY = os.environ.get("MCP_JWT_SIGNING_KEY")
STORAGE_ENCRYPTION_KEY = os.environ.get("MCP_STORAGE_ENCRYPTION_KEY")

OAUTH_ENABLED = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET and BASE_URL)

ROOT.mkdir(parents=True, exist_ok=True)

auth = None
if OAUTH_ENABLED:
    from cryptography.fernet import Fernet
    from fastmcp.server.auth.providers.github import GitHubProvider
    from key_value.aio.stores.filetree import (
        FileTreeStore,
        FileTreeV1CollectionSanitizationStrategy,
        FileTreeV1KeySanitizationStrategy,
    )
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    oauth_dir = (ROOT / "oauth").resolve()
    oauth_dir.mkdir(parents=True, exist_ok=True)
    storage = FileTreeStore(
        data_directory=oauth_dir,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(oauth_dir),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(oauth_dir),
    )
    if STORAGE_ENCRYPTION_KEY:
        storage = FernetEncryptionWrapper(key_value=storage, fernet=Fernet(STORAGE_ENCRYPTION_KEY))

    auth = GitHubProvider(
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        base_url=BASE_URL,
        redirect_path="/auth/github/callback",
        jwt_signing_key=JWT_SIGNING_KEY,
        client_storage=storage,
    )

mcp = FastMCP("files-server", auth=auth)


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


if __name__ == "__main__":
    mcp.run(transport="http", host=HOST, port=PORT)
