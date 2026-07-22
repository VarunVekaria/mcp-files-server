"""A minimal MCP server exposing sandboxed local file/data tools over stdio.

Config via environment variables (all optional):
  MCP_ROOT   Directory all file access is confined to. Default: ./data

  OpenTelemetry tracing is native to FastMCP -- it emits spans via the OTel
  API as long as some SDK TracerProvider is registered, which this file does
  directly (see below) when OTEL_EXPORTER_OTLP_ENDPOINT is set. Standard OTel
  env vars configure it: OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES,
  OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS,
  OTEL_EXPORTER_OTLP_PROTOCOL ("http/protobuf" or "grpc", default "grpc").
  Deliberately *not* run via the `opentelemetry-instrument` CLI launcher: on
  Windows that wrapper spawns this script as a second child process (Windows
  has no real exec()) and relays stdio to it, which breaks Claude Desktop's
  native pipe handling for stdio-transport MCP servers.

Local debug:   uv run fastmcp dev server.py
Run server:    uv run server.py
"""

import difflib
import hashlib
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fastmcp import FastMCP

# --- Configuration -----------------------------------------------------------
ROOT = Path(os.environ.get("MCP_ROOT", "./data")).resolve()
ROOT.mkdir(parents=True, exist_ok=True)

if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    if os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL") == "http/protobuf":
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
    else:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

    provider = TracerProvider(resource=Resource.create())
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)

mcp = FastMCP("files-server")


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


@mcp.tool()
def grep_lines(path: str, pattern: str, max_matches: int = 50) -> list[dict]:
    """Search a text file under the root with a regex and return matching
    lines as [{line_number, text}], capped at `max_matches`."""
    regex = re.compile(pattern, re.IGNORECASE)
    matches: list[dict] = []
    with _safe(path).open(encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, start=1):
            if regex.search(line):
                matches.append({"line_number": i, "text": line.rstrip("\n")})
                if len(matches) >= max_matches:
                    break
    return matches


@mcp.tool()
def write_file(path: str, content: str, overwrite: bool = False) -> str:
    """Write UTF-8 text to a file under the root, creating parent directories
    as needed. Fails if the file already exists unless `overwrite` is True."""
    p = _safe(path)
    if p.exists() and not overwrite:
        raise ValueError(f"{path} already exists; pass overwrite=True to replace it")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} chars to {path}"


@mcp.tool()
def file_info(path: str) -> dict:
    """Return size, modification time, and line count for a file under the root."""
    p = _safe(path)
    st = p.stat()
    try:
        line_count = sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
    except Exception:
        line_count = None
    return {
        "path": path,
        "size_bytes": st.st_size,
        "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "line_count": line_count,
    }


@mcp.tool()
def hash_file(path: str, algorithm: str = "sha256") -> str:
    """Compute a hex digest of a file under the root using the given hashlib
    algorithm (default sha256)."""
    h = hashlib.new(algorithm)
    with _safe(path).open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@mcp.tool()
def diff_files(path_a: str, path_b: str) -> str:
    """Return a unified diff between two text files under the root."""
    a = _safe(path_a).read_text(encoding="utf-8").splitlines(keepends=True)
    b = _safe(path_b).read_text(encoding="utf-8").splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=path_a, tofile=path_b)) or "(no differences)"


@mcp.tool()
def word_frequency(path: str, top_n: int = 10) -> list[list]:
    """Return the `top_n` most common words (case-insensitive, alphabetic) in
    a text file under the root, as [word, count] pairs."""
    text = _safe(path).read_text(encoding="utf-8", errors="ignore").lower()
    words = re.findall(r"[a-z']+", text)
    return [[w, c] for w, c in Counter(words).most_common(top_n)]


# --- Resource: load file contents by URI (file://<path>) ---------------------
@mcp.resource("file://{path}")
def file_resource(path: str) -> str:
    return _safe(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run(transport="stdio")
