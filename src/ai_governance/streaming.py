"""Streaming replies.

A client that sends `stream: true` expects the reply as a series of
server-sent events. The proxy cannot scan a reply it has only seen part of,
so it asks the provider for the complete reply, scans it, and only then
sends it to the client in streaming format.

The client gets the format it asked for and nothing unscanned leaves the
proxy. The cost is that text does not appear word by word: it arrives all
at once when the model has finished.
"""

import json
from collections.abc import Iterator
from typing import Any

# Request fields that only make sense for a streamed upstream call.
STREAM_REQUEST_FIELDS = ("stream", "stream_options")


def wants_stream(extra_fields: dict[str, Any] | None) -> bool:
    """True if the client asked for a streamed reply."""
    return bool((extra_fields or {}).get("stream"))


def wants_usage(extra_fields: dict[str, Any] | None) -> bool:
    """True if the client asked for token usage at the end of the stream."""
    options = (extra_fields or {}).get("stream_options")
    return isinstance(options, dict) and bool(options.get("include_usage"))


def without_stream_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """The request as it is sent to the provider: the same, but not streamed."""
    return {key: value for key, value in payload.items() if key not in STREAM_REQUEST_FIELDS}


def can_stream(completion: Any) -> bool:
    """True if the reply has the usual chat completion shape."""
    return isinstance(completion, dict) and isinstance(completion.get("choices"), list)


def completion_to_events(completion: dict[str, Any], include_usage: bool = False) -> Iterator[str]:
    """Turn a complete, already scanned chat completion into server-sent events.

    Each choice is sent as one chunk carrying the whole message, followed by a
    chunk carrying its finish reason, then the `[DONE]` marker.
    """
    base = {key: completion[key] for key in ("id", "created", "model", "system_fingerprint") if key in completion}
    base["object"] = "chat.completion.chunk"

    def event(body: dict[str, Any]) -> str:
        return f"data: {json.dumps({**base, **body})}\n\n"

    for position, choice in enumerate(completion["choices"]):
        if not isinstance(choice, dict):
            continue
        index = choice.get("index", position)
        message = choice.get("message")
        delta = dict(message) if isinstance(message, dict) else {}
        tool_calls = delta.get("tool_calls")
        if isinstance(tool_calls, list):
            # In a stream every tool call carries its position in the list.
            delta["tool_calls"] = [
                {"index": number, **call} if isinstance(call, dict) else call for number, call in enumerate(tool_calls)
            ]
        yield event({"choices": [{"index": index, "delta": delta, "finish_reason": None}]})
        yield event({"choices": [{"index": index, "delta": {}, "finish_reason": choice.get("finish_reason")}]})

    if include_usage and "usage" in completion:
        yield event({"choices": [], "usage": completion["usage"]})

    yield "data: [DONE]\n\n"
