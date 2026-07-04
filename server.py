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

import os
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


# --- Resource: load file contents by URI (file://<path>) ---------------------
@mcp.resource("file://{path}")
def file_resource(path: str) -> str:
    return _safe(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run(transport="stdio")
