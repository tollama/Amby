from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable, TypeVar
from urllib import request


T = TypeVar("T")


class AmbyPolicyError(RuntimeError):
    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        super().__init__(f"Amby policy decision={decision.get('decision')}")


@dataclass(frozen=True)
class AmbyClient:
    base_url: str = "http://localhost:8080"
    agent_id: str = "agent"
    framework: str = "generic"
    timeout: float = 10.0

    def evaluate_tool_call(
        self,
        *,
        tool_name: str,
        action: str | None = None,
        method: str = "POST",
        url: str | None = None,
        arguments: dict[str, Any] | None = None,
        approval_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/agent/tool-calls/evaluate",
            {
                "agent_id": self.agent_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "action": action or tool_name.rsplit(".", 1)[-1],
                "method": method,
                "url": url,
                "arguments": arguments or {},
                "approval_id": approval_id,
            },
        )

    def evaluate_memory_write(
        self,
        text: str,
        *,
        session_id: str | None = None,
        source_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.evaluate_context(
            hook_type="memory_write",
            texts=[text],
            session_id=session_id,
            source_ref=source_ref,
            metadata=metadata,
        )

    def evaluate_retrieval_context(
        self,
        texts: list[str],
        *,
        session_id: str | None = None,
        source_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.evaluate_context(
            hook_type="retrieval_context",
            texts=texts,
            session_id=session_id,
            source_ref=source_ref,
            metadata=metadata,
        )

    def evaluate_context(
        self,
        *,
        hook_type: str,
        texts: list[str],
        session_id: str | None = None,
        source_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/frameworks/context/evaluate",
            {
                "request_id": str(uuid.uuid4()),
                "framework": self.framework,
                "hook_type": hook_type,
                "agent_id": self.agent_id,
                "session_id": session_id,
                "texts": texts,
                "source_ref": source_ref,
                "metadata": metadata or {},
            },
        )

    def wrap_tool(
        self,
        tool_name: str,
        func: Callable[..., T],
        *,
        action: str | None = None,
        method: str = "POST",
        url: str | None = None,
    ) -> Callable[..., T]:
        def wrapped(*args: Any, **kwargs: Any) -> T:
            decision = self.evaluate_tool_call(
                tool_name=tool_name,
                action=action,
                method=method,
                url=url,
                arguments={"args": len(args), "kwargs": sorted(kwargs)},
            )
            if decision.get("decision") != "allow":
                raise AmbyPolicyError(decision)
            return func(*args, **kwargs)

        return wrapped

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps({key: value for key, value in payload.items() if value is not None}).encode("utf-8")
        req = request.Request(
            f"{self.base_url.rstrip('/')}{path}",
            data=body,
            method="POST",
            headers={"content-type": "application/json"},
        )
        with request.urlopen(req, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))


class LangGraphAdapter(AmbyClient):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, framework="langgraph", **kwargs)


class CrewAIAdapter(AmbyClient):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, framework="crewai", **kwargs)


class LlamaIndexAdapter(AmbyClient):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, framework="llamaindex", **kwargs)

