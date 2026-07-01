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
        segments.extend(_openai_response_item_segments(("input",), payload.get("input")))
        messages = payload.get("messages")
        if isinstance(messages, list):
            for index, message in enumerate(messages):
                if not isinstance(message, dict):
                    continue
                content = message.get("content")
                segments.extend(_content_segments(("messages", index, "content"), content))
                segments.extend(_openai_function_call_segments(("messages", index), message))
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
                    if not isinstance(message, dict):
                        continue
                    if isinstance(message.get("content"), str):
                        segments.append(TextSegment(("choices", choice_index, key, "content"), message["content"]))
                    segments.extend(_openai_function_call_segments(("choices", choice_index, key), message))
        segments.extend(_openai_response_item_segments(("output",), payload.get("output")))
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
        if isinstance(delta, dict) and isinstance(delta.get("partial_json"), str):
            segments.append(TextSegment(("delta", "partial_json"), delta["partial_json"]))
        content_block = payload.get("content_block")
        if isinstance(content_block, dict) and isinstance(content_block.get("text"), str):
            segments.append(TextSegment(("content_block", "text"), content_block["text"]))
        if isinstance(content_block, dict) and content_block.get("type") == "tool_use":
            segments.extend(_leaf_string_segments(("content_block", "input"), content_block.get("input")))
    return segments


def _content_segments(base_path: tuple[object, ...], content: Any) -> list[TextSegment]:
    if isinstance(content, str):
        return [TextSegment(base_path, content)]
    if not isinstance(content, list):
        return []

    segments: list[TextSegment] = []
    for index, item in enumerate(content):
        if not isinstance(item, dict):
            continue
        if item.get("type") in {"text", "input_text", "output_text"} and isinstance(item.get("text"), str):
            segments.append(TextSegment((*base_path, index, "text"), item["text"]))
            continue
        if item.get("type") == "tool_result":
            segments.extend(_tool_result_segments((*base_path, index), item))
            continue
        if item.get("type") == "tool_use":
            segments.extend(_leaf_string_segments((*base_path, index, "input"), item.get("input")))
    return segments


def _tool_result_segments(base_path: tuple[object, ...], item: dict[str, Any]) -> list[TextSegment]:
    if "content" in item:
        content = item.get("content")
        if isinstance(content, list):
            return _content_segments((*base_path, "content"), content)
        return _leaf_string_segments((*base_path, "content"), content)
    if "output" in item:
        return _leaf_string_segments((*base_path, "output"), item.get("output"))
    return []


def _openai_function_call_segments(base_path: tuple[object, ...], message: dict[str, Any]) -> list[TextSegment]:
    segments: list[TextSegment] = []
    function_call = message.get("function_call")
    if isinstance(function_call, dict):
        segments.extend(_leaf_string_segments((*base_path, "function_call", "arguments"), function_call.get("arguments")))

    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for index, tool_call in enumerate(tool_calls):
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if isinstance(function, dict):
                segments.extend(_leaf_string_segments((*base_path, "tool_calls", index, "function", "arguments"), function.get("arguments")))
            segments.extend(_leaf_string_segments((*base_path, "tool_calls", index, "arguments"), tool_call.get("arguments")))
    return segments


def _openai_response_item_segments(base_path: tuple[object, ...], items: Any) -> list[TextSegment]:
    if isinstance(items, str):
        return [TextSegment(base_path, items)]
    if not isinstance(items, list):
        return []

    segments: list[TextSegment] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        item_path = (*base_path, index)
        item_type = item.get("type")
        if item_type == "message":
            segments.extend(_content_segments((*item_path, "content"), item.get("content")))
        elif item_type in {"function_call", "tool_call"}:
            segments.extend(_leaf_string_segments((*item_path, "arguments"), item.get("arguments")))
        elif item_type in {"function_call_output", "tool_result"}:
            segments.extend(_tool_result_segments(item_path, item))
        else:
            segments.extend(_content_segments((*item_path, "content"), item.get("content")))
    return segments


def _leaf_string_segments(base_path: tuple[object, ...], value: Any) -> list[TextSegment]:
    if isinstance(value, str):
        return [TextSegment(base_path, value)]
    if isinstance(value, list):
        segments: list[TextSegment] = []
        for index, item in enumerate(value):
            segments.extend(_leaf_string_segments((*base_path, index), item))
        return segments
    if isinstance(value, dict):
        segments = []
        for key, item in value.items():
            segments.extend(_leaf_string_segments((*base_path, key), item))
        return segments
    return []


def _set_path(root: Any, path: tuple[object, ...], value: str) -> None:
    cursor = root
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
