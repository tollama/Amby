from __future__ import annotations

import os
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import AppConfig, UpstreamConfig


HOP_BY_HOP_HEADERS = {
    "connection",
    "content-encoding",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


@dataclass(frozen=True)
class UpstreamTarget:
    config: UpstreamConfig
    url: str
    headers: dict[str, str]


class MissingApiKeyError(RuntimeError):
    pass


_DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0)
_DEFAULT_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=30.0)
_CURRENT_CLIENT: ContextVar[httpx.AsyncClient | None] = ContextVar("amby_upstream_client", default=None)


def create_upstream_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT, limits=_DEFAULT_LIMITS)


def bind_upstream_client(client: httpx.AsyncClient) -> Token[httpx.AsyncClient | None]:
    return _CURRENT_CLIENT.set(client)


def reset_upstream_client(token: Token[httpx.AsyncClient | None]) -> None:
    _CURRENT_CLIENT.reset(token)


def resolve_target(
    *,
    app_config: AppConfig,
    provider: str,
    endpoint: str,
    model: str,
    incoming_headers: dict[str, str],
) -> UpstreamTarget:
    upstream = app_config.match_upstream(model or "*", provider)
    headers = _forward_headers(incoming_headers)
    headers["content-type"] = "application/json"

    if upstream.provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise MissingApiKeyError("OPENAI_API_KEY is required for OpenAI upstream calls")
        headers["authorization"] = f"Bearer {api_key}"
    elif upstream.provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise MissingApiKeyError("ANTHROPIC_API_KEY is required for Anthropic upstream calls")
        headers["x-api-key"] = api_key
        headers.setdefault("anthropic-version", incoming_headers.get("anthropic-version", "2023-06-01"))
    else:
        raise ValueError(f"Unsupported upstream provider: {upstream.provider}")

    return UpstreamTarget(config=upstream, url=f"{upstream.base_url}{endpoint}", headers=headers)


async def post_json(target: UpstreamTarget, payload: dict[str, Any]) -> httpx.Response:
    client = _CURRENT_CLIENT.get()
    if client is not None:
        return await client.post(target.url, headers=target.headers, json=payload)
    async with create_upstream_client() as client:
        return await client.post(target.url, headers=target.headers, json=payload)


def response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() not in HOP_BY_HOP_HEADERS}


def _forward_headers(incoming: dict[str, str]) -> dict[str, str]:
    headers = {
        key.lower(): value
        for key, value in incoming.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and not key.lower().startswith("x-guardrail-")
    }
    headers.pop("authorization", None)
    headers.pop("x-api-key", None)
    return headers
