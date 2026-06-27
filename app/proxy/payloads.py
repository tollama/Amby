from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TextSegment:
    path: tuple[object, ...]
    text: str


def extract_text_segments(provider: str, direction: str, payload: Any) -> list[TextSegment]:
    if not isinstance(payload, dict):
        return []
    if provider == "openai":
        return _extract_openai(direction, payload)
    if provider == "anthropic":
        return _extract_anthropic(direction, payload)
    return []


def apply_text_replacements(payload: dict[str, Any], segments: list[TextSegment], replacements: list[str]) -> dict[str, Any]:
    updated = copy.deepcopy(payload)
    for segment, replacement in zip(segments, replacements, strict=False):
        _set_path(updated, segment.path, replacement)
    return updated


def _extract_openai(direction: str, payload: dict[str, Any]) -> list[TextSegment]:
    segments: list[TextSegment] = []
    if direction == "input":
        if isinstance(payload.get("prompt"), str):
            segments.append(TextSegment(("prompt",), payload["prompt"]))
        messages = payload.get("messages")
        if isinstance(messages, list):
            for index, message in enumerate(messages):
                if not isinstance(message, dict):
                    continue
                content = message.get("content")
                segments.extend(_content_segments(("messages", index, "content"), content))
    else:
        choices = payload.get("choices")
        if isinstance(choices, list):
            for choice_index, choice in enumerate(choices):
                if not isinstance(choice, dict):
                    continue
                if isinstance(choice.get("text"), str):
                    segments.append(TextSegment(("choices", choice_index, "text"), choice["text"]))
                for key in ("message", "delta"):
                    message = choice.get(key)
                    if isinstance(message, dict) and isinstance(message.get("content"), str):
                        segments.append(TextSegment(("choices", choice_index, key, "content"), message["content"]))
    return segments


def _extract_anthropic(direction: str, payload: dict[str, Any]) -> list[TextSegment]:
    segments: list[TextSegment] = []
    if direction == "input":
        system = payload.get("system")
        segments.extend(_content_segments(("system",), system))
        messages = payload.get("messages")
        if isinstance(messages, list):
            for index, message in enumerate(messages):
                if not isinstance(message, dict):
                    continue
                segments.extend(_content_segments(("messages", index, "content"), message.get("content")))
    else:
        if isinstance(payload.get("completion"), str):
            segments.append(TextSegment(("completion",), payload["completion"]))
        segments.extend(_content_segments(("content",), payload.get("content")))
        delta = payload.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("text"), str):
            segments.append(TextSegment(("delta", "text"), delta["text"]))
        content_block = payload.get("content_block")
        if isinstance(content_block, dict) and isinstance(content_block.get("text"), str):
            segments.append(TextSegment(("content_block", "text"), content_block["text"]))
    return segments


def _content_segments(base_path: tuple[object, ...], content: Any) -> list[TextSegment]:
    if isinstance(content, str):
        return [TextSegment(base_path, content)]
    if not isinstance(content, list):
        return []

    segments: list[TextSegment] = []
    for index, item in enumerate(content):
        if isinstance(item, dict) and item.get("type") in {"text", "input_text", "output_text"} and isinstance(item.get("text"), str):
            segments.append(TextSegment((*base_path, index, "text"), item["text"]))
    return segments


def _set_path(root: Any, path: tuple[object, ...], value: str) -> None:
    cursor = root
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
