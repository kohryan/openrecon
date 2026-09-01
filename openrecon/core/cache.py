"""A tiny on-disk response cache so re-scans don't re-hammer public APIs."""

from __future__ import annotations

import contextlib
import hashlib
import json
import time
from pathlib import Path
from typing import Any


class DiskCache:
    def __init__(self, directory: Path, ttl: int = 3600, enabled: bool = True) -> None:
        self.dir = Path(directory)
        self.ttl = ttl
        self.enabled = enabled
        if self.enabled:
            self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.dir / digest[:2] / f"{digest}.json"

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        p = self._path(key)
        if not p.exists():
            return None
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if time.time() - payload.get("_ts", 0) > self.ttl:
            return None
        return payload.get("data")

    def set(self, key: str, data: Any) -> None:
        if not self.enabled:
            return
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError, TypeError):
            p.write_text(json.dumps({"_ts": time.time(), "data": data}), encoding="utf-8")

    def clear(self) -> int:
        if not self.dir.exists():
            return 0
        count = 0
        for f in self.dir.rglob("*.json"):
            f.unlink(missing_ok=True)
            count += 1
        return count
