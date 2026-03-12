#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tamper-evident audit logger with hash chaining + HMAC signature."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLogger:
    def __init__(
        self,
        log_path: str,
        state_path: str,
        key_path: str,
    ) -> None:
        self.log_path = Path(log_path)
        self.state_path = Path(state_path)
        self.key_path = Path(key_path)
        self.lock_path = self.log_path.parent / ".audit.lock"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(exist_ok=True)
        self._last_hash = self._load_last_hash()
        self._hmac_key = self._load_key()

    def _load_key(self) -> bytes:
        if not self.key_path.exists():
            raise RuntimeError(f"HMAC key not found: {self.key_path}")
        key = self.key_path.read_text(encoding="utf-8").strip()
        if not key:
            raise RuntimeError("HMAC key file is empty")
        return key.encode("utf-8")

    def _load_last_hash(self) -> str:
        if not self.state_path.exists():
            return "GENESIS"
        content = self.state_path.read_text(encoding="utf-8").strip()
        return content if content else "GENESIS"

    @staticmethod
    def _stable_json(record: Dict[str, Any]) -> str:
        return json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

    def _sign(self, data: str) -> str:
        return hmac.new(self._hmac_key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def write_event(
        self,
        *,
        event_type: str,
        pid: Optional[int] = None,
        user: Optional[str] = None,
        command: str = "",
        file_path: str = "",
        network: str = "",
        result: str = "ok",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self.lock_path.open("r+", encoding="utf-8") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            prev_hash = self._load_last_hash()
            base = {
                "timestamp_ms": int(time.time() * 1000),
                "event_type": event_type,
                "pid": pid if pid is not None else -1,
                "user": user or "unknown",
                "command": command,
                "file": file_path,
                "network": network,
                "result": result,
                "details": details or {},
                "prev_hash": prev_hash,
            }

            digest_input = self._stable_json(base)
            record_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
            signature = self._sign(digest_input)

            final_record = dict(base)
            final_record["hash"] = record_hash
            final_record["sig"] = signature

            self._append_record(final_record)
            self._last_hash = record_hash
            self.state_path.write_text(record_hash + "\n", encoding="utf-8")
            fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)
            return final_record

    def _append_record(self, record: Dict[str, Any]) -> None:
        with self.log_path.open("a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(self._stable_json(record) + "\n")
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
