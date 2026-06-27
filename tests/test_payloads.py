from app.proxy.payloads import apply_text_replacements, extract_text_segments


def test_openai_input_segments_and_replacements() -> None:
    payload = {
        "model": "gpt-test",
        "messages": [
            {"role": "user", "content": "email alice@example.com"},
            {"role": "user", "content": [{"type": "text", "text": "ssn 123-45-6789"}]},
        ],
    }

    segments = extract_text_segments("openai", "input", payload)
    updated = apply_text_replacements(payload, segments, ["email [REDACTED_EMAIL]", "ssn [REDACTED_SSN]"])

    assert [segment.text for segment in segments] == ["email alice@example.com", "ssn 123-45-6789"]
    assert updated["messages"][0]["content"] == "email [REDACTED_EMAIL]"
    assert updated["messages"][1]["content"][0]["text"] == "ssn [REDACTED_SSN]"


def test_anthropic_output_segments() -> None:
    payload = {"content": [{"type": "text", "text": "hello alice@example.com"}]}

    segments = extract_text_segments("anthropic", "output", payload)

    assert len(segments) == 1
    assert segments[0].text == "hello alice@example.com"
