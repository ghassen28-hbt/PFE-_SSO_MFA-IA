import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional


DATA_DIR = Path(os.getenv("BIOMETRIC_DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

STORE_PATH = DATA_DIR / "biometric_profiles.json"
_LOCK = Lock()


def _read_store() -> dict:
    if not STORE_PATH.exists():
        return {}

    with STORE_PATH.open("r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}


def _write_store(data: dict) -> None:
    tmp_path = STORE_PATH.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp_path.replace(STORE_PATH)


def load_profile(user_id: str) -> Optional[dict]:
    with _LOCK:
        data = _read_store()
        return data.get(user_id)


def save_profile(
    user_id: str,
    username: str,
    embedding: list,
    model: str,
    quality_score: float,
    face_confidence: float,
    extra_meta: dict | None = None,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "user_id": user_id,
        "username": username or "",
        "embedding": embedding,
        "model": model,
        "quality_score": quality_score,
        "face_confidence": face_confidence,
        "enrolled_at": now,
        "updated_at": now,
        "meta": extra_meta or {},
    }

    with _LOCK:
        data = _read_store()
        data[user_id] = record
        _write_store(data)

    return record