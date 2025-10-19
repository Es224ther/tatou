# -*- coding: utf-8 -*-
import json, logging, uuid
from datetime import datetime
from typing import Any, Dict

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        
        extra = getattr(record, "extra", None) or getattr(record, "__dict__", {})
        ctx = extra.get("ctx") if isinstance(extra, dict) else None
        if isinstance(ctx, dict):
            base.update(ctx)
        return json.dumps(base, ensure_ascii=False)

def setup_json_logging(level: str = "INFO"):
    root = logging.getLogger()
    root.handlers.clear()
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

class CtxAdapter(logging.LoggerAdapter):
    def __init__(self, logger, ctx: Dict[str, Any]):  # type: ignore[no-untyped-def]
        super().__init__(logger, {"ctx": ctx})
    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        ctx = extra.get("ctx", {})
        merged = {**self.extra["ctx"], **ctx}
        kwargs["extra"] = {"ctx": merged}
        return msg, kwargs
