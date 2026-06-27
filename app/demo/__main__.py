from __future__ import annotations

import json
import os
import sys
from urllib import request


def main() -> int:
    base_url = os.getenv("AMBY_URL", "http://localhost:8080").rstrip("/")
    url = f"{base_url}/demo/inject"
    req = request.Request(url, method="POST")
    try:
        with request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print(f"demo injection failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
