"""Core: database, config, event bus, settings, dashboard. Always on."""
from diysca.core.modules import Module

MODULE = Module(
    name="core", title="Core", description="Database, configuration, events, dashboard, settings import / export.",
    nav=[("dashboard", "/", "Dashboard", "M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z", 0)],
    settings_tabs=[("general", "/settings", "General", 0), ("backup", "/settings/backup", "Import / Export", 90)],
    mcp_tools=(),
    openapi_tags=[{"name": "mcp", "description": "Model Context Protocol endpoint (JSON-RPC 2.0, streamable HTTP, JSON responses)."},
                  {"name": "health", "description": "Liveness probe without authentication."}],
)
