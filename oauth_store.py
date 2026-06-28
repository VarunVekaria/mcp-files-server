"""SQLite persistence for the GitHub-delegated OAuth provider.

Pure storage layer: no OAuth protocol knowledge, just get/save/delete
helpers for the rows `github_oauth.GitHubOAuthProvider` needs. Backed by a
single sqlite file so registered clients and issued tokens survive process
restarts (Fly.io machines auto-stop/restart by default).
"""

import json
import sqlite3
import time
from pathlib import Path

from mcp.server.auth.provider import AccessToken, AuthorizationCode, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

PENDING_GITHUB_TTL_SECONDS = 600


def init_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            data TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            data TEXT NOT NULL,
            expires_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS access_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            data TEXT NOT NULL,
            expires_at REAL
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            data TEXT NOT NULL,
            expires_at REAL
        );
        CREATE TABLE IF NOT EXISTS pending_github (
            state TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            expires_at REAL NOT NULL
        );
        """
    )
    conn.commit()
    return conn


# --- clients -----------------------------------------------------------------
def get_client(conn: sqlite3.Connection, client_id: str) -> OAuthClientInformationFull | None:
    row = conn.execute("SELECT data FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    if row is None:
        return None
    return OAuthClientInformationFull.model_validate_json(row[0])


def save_client(conn: sqlite3.Connection, client_info: OAuthClientInformationFull) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO clients (client_id, data) VALUES (?, ?)",
        (client_info.client_id, client_info.model_dump_json()),
    )
    conn.commit()


# --- authorization codes ------------------------------------------------------
def get_auth_code(conn: sqlite3.Connection, code: str) -> AuthorizationCode | None:
    row = conn.execute(
        "SELECT data, expires_at FROM auth_codes WHERE code = ?", (code,)
    ).fetchone()
    if row is None:
        return None
    data, expires_at = row
    if expires_at < time.time():
        delete_auth_code(conn, code)
        return None
    return AuthorizationCode.model_validate_json(data)


def save_auth_code(conn: sqlite3.Connection, auth_code: AuthorizationCode) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO auth_codes (code, client_id, data, expires_at) VALUES (?, ?, ?, ?)",
        (auth_code.code, auth_code.client_id, auth_code.model_dump_json(), auth_code.expires_at),
    )
    conn.commit()


def delete_auth_code(conn: sqlite3.Connection, code: str) -> None:
    conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
    conn.commit()


# --- access tokens -------------------------------------------------------------
def get_access_token(conn: sqlite3.Connection, token: str) -> AccessToken | None:
    row = conn.execute(
        "SELECT data, expires_at FROM access_tokens WHERE token = ?", (token,)
    ).fetchone()
    if row is None:
        return None
    data, expires_at = row
    if expires_at is not None and expires_at < time.time():
        delete_access_token(conn, token)
        return None
    return AccessToken.model_validate_json(data)


def save_access_token(conn: sqlite3.Connection, access_token: AccessToken) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO access_tokens (token, client_id, data, expires_at) VALUES (?, ?, ?, ?)",
        (
            access_token.token,
            access_token.client_id,
            access_token.model_dump_json(),
            access_token.expires_at,
        ),
    )
    conn.commit()


def delete_access_token(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
    conn.commit()


# --- refresh tokens -------------------------------------------------------------
def get_refresh_token(conn: sqlite3.Connection, token: str) -> RefreshToken | None:
    row = conn.execute(
        "SELECT data, expires_at FROM refresh_tokens WHERE token = ?", (token,)
    ).fetchone()
    if row is None:
        return None
    data, expires_at = row
    if expires_at is not None and expires_at < time.time():
        delete_refresh_token(conn, token)
        return None
    return RefreshToken.model_validate_json(data)


def save_refresh_token(conn: sqlite3.Connection, refresh_token: RefreshToken) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO refresh_tokens (token, client_id, data, expires_at) VALUES (?, ?, ?, ?)",
        (
            refresh_token.token,
            refresh_token.client_id,
            refresh_token.model_dump_json(),
            refresh_token.expires_at,
        ),
    )
    conn.commit()


def delete_refresh_token(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
    conn.commit()


# --- pending GitHub round-trips ------------------------------------------------
def save_pending_github(conn: sqlite3.Connection, state: str, data: dict) -> None:
    conn.execute("DELETE FROM pending_github WHERE expires_at < ?", (time.time(),))
    conn.execute(
        "INSERT OR REPLACE INTO pending_github (state, data, expires_at) VALUES (?, ?, ?)",
        (state, json.dumps(data), time.time() + PENDING_GITHUB_TTL_SECONDS),
    )
    conn.commit()


def pop_pending_github(conn: sqlite3.Connection, state: str) -> dict | None:
    row = conn.execute(
        "SELECT data, expires_at FROM pending_github WHERE state = ?", (state,)
    ).fetchone()
    conn.execute("DELETE FROM pending_github WHERE state = ?", (state,))
    conn.commit()
    if row is None:
        return None
    data, expires_at = row
    if expires_at < time.time():
        return None
    return json.loads(data)
