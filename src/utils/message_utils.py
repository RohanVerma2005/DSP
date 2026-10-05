import json
from typing import Any, Dict

def canonical_dumps(data: Dict[str, Any]) -> bytes:
    """
    Serializes a dictionary to deterministic, canonical UTF-8 bytes.
    Alphabetically sorts keys and eliminates whitespace to prevent signature mismatch.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def canonical_loads(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Deserializes UTF-8 JSON bytes back into a Python dictionary.
    """
    return json.loads(raw_bytes.decode("utf-8"))