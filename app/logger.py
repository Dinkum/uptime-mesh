from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from types import TracebackType
from typing import Any, Dict, Iterator, Mapping, Optional

_LEVEL_SYMBOLS: Dict[int, str] = {
    logging.DEBUG: "(?)",
    logging.INFO: "(*)",
    logging.WARNING: "(!)",
    logging.ERROR: "(x)",
    logging.CRITICAL: "(X)",
}

_LOG_CONTEXT: ContextVar[Dict[str, Any]] = ContextVar("log_context", default={})


class _UptimeFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        created = datetime.fromtimestamp(record.created, tz=timezone.utc)
        date_part = created.strftime("%Y-%m-%d")
        time_part = created.strftime("%H:%M:%S.%f")[:-3]

        level = record.levelname
        symbol = getattr(record, "symbol", _LEVEL_SYMBOLS.get(record.levelno, "(?)"))
        category = getattr(record, "category", record.name)
        event = getattr(record, "event", "")
        message = record.getMessage()
        fields: Mapping[str, Any] = getattr(record, "fields", {})
        mutable_fields = dict(fields)

        parts = [
            f"{date_part} {time_part}",
            f"{level:<8}",
            str(category),
        ]

        if event:
            if event == "operation.step":
                step_name = str(mutable_fields.pop("step", "step"))
                child_name = mutable_fields.pop("child", None)
                mutable_fields.pop("step_depth", None)
                if child_name:
                    parts.append(f"{symbol} >> {step_name} >> {child_name}")
                else:
                    parts.append(f"{symbol} >> {step_name}")
            else:
                parts.append(f"{symbol} {event}")
        elif message:
            parts.append(f"{symbol} {message}")

        if event and message:
            parts.append(str(message))

        if mutable_fields:
            field_parts = [f"{key}: {value}" for key, value in mutable_fields.items()]
            parts.extend(field_parts)

        formatted = " | ".join(parts)
        if record.exc_info:
            return f"{formatted}\n{self.formatException(record.exc_info)}"
        return formatted


@dataclass(frozen=True)
class Operation:
    logger: "BoundLogger"
    name: str
    message: str
    fields: Dict[str, Any]
    start_time: float = 0.0

    async def __aenter__(self) -> "Operation":
        object.__setattr__(self, "start_time", perf_counter())
        self.logger.info(
            "operation.start",
            self.message,
            operation=self.name,
            **self.fields,
        )
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        duration_ms = (perf_counter() - self.start_time) * 1000
        if exc_type is None:
            self.logger.info(
                "operation.complete",
                "Completed",
                operation=self.name,
                duration_ms=round(duration_ms, 1),
            )
        else:
            self.logger.exception(
                "operation.error",
                "Failed",
                operation=self.name,
                duration_ms=round(duration_ms, 1),
                error_type=exc_type.__name__,
            )

    def _step(self, severity: int, name: str, message: str, **fields: Any) -> None:
        payload = {
            "operation": self.name,
            "step": name,
            **fields,
        }
        if severity == logging.WARNING:
            self.logger.warning("operation.step", message, **payload)
            return
        if severity >= logging.ERROR:
            self.logger.error("operation.step", message, **payload)
            return
        if severity == logging.DEBUG:
            self.logger.debug("operation.step", message, **payload)
            return
        self.logger.info("operation.step", message, **payload)

    def step(self, name: str, message: str, **fields: Any) -> None:
        self._step(logging.INFO, name, message, **fields)

    def step_debug(self, name: str, message: str, **fields: Any) -> None:
        self._step(logging.DEBUG, name, message, **fields)

    def step_warning(self, name: str, message: str, **fields: Any) -> None:
        self._step(logging.WARNING, name, message, **fields)

    def step_error(self, name: str, message: str, **fields: Any) -> None:
        self._step(logging.ERROR, name, message, **fields)

    def child(self, parent_step: str, child_name: str, message: str, **fields: Any) -> None:
        self._step(
            logging.INFO,
            parent_step,
            message,
            child=child_name,
            step_depth=2,
            **fields,
        )


class BoundLogger:
    def __init__(self, category: str, fields: Optional[Mapping[str, Any]] = None) -> None:
        self._category = category
        self._fields: Dict[str, Any] = dict(fields or {})

    def bind(self, **fields: Any) -> "BoundLogger":
        merged = dict(self._fields)
        merged.update(fields)
        return BoundLogger(self._category, merged)

    @contextmanager
    def context(self, **fields: Any) -> Iterator[None]:
        current = dict(_LOG_CONTEXT.get())
        current.update(fields)
        token = _LOG_CONTEXT.set(current)
        try:
            yield
        finally:
            _LOG_CONTEXT.reset(token)

    def operation(self, name: str, message: str, **fields: Any) -> Operation:
        return Operation(self, name=name, message=message, fields=fields)

    def debug(self, event: str, message: str, **fields: Any) -> None:
        self._log(logging.DEBUG, event, message, **fields)

    def info(self, event: str, message: str, **fields: Any) -> None:
        self._log(logging.INFO, event, message, **fields)

    def warning(self, event: str, message: str, **fields: Any) -> None:
        self._log(logging.WARNING, event, message, **fields)

    def error(self, event: str, message: str, **fields: Any) -> None:
        self._log(logging.ERROR, event, message, **fields)

    def exception(self, event: str, message: str, **fields: Any) -> None:
        self._log(logging.ERROR, event, message, exc_info=True, **fields)

    def critical(self, event: str, message: str, **fields: Any) -> None:
        self._log(logging.CRITICAL, event, message, **fields)

    def _log(
        self,
        severity: int,
        event: str,
        message: str,
        *,
        exc_info: Any = None,
        **fields: Any,
    ) -> None:
        base_fields: Dict[str, Any] = {}
        base_fields.update(_LOG_CONTEXT.get())
        base_fields.update(self._fields)
        base_fields.update(fields)

        logger = logging.getLogger("uptimemesh")
        logger.log(
            severity,
            message,
            extra={
                "category": self._category,
                "event": event,
                "symbol": _LEVEL_SYMBOLS.get(severity, "(?)"),
                "fields": base_fields,
            },
            exc_info=exc_info,
        )


def configure_logging(log_level: str, log_file: Optional[str]) -> None:
    formatter = _UptimeFormatter()

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    handlers: list[logging.Handler] = [stream_handler]

    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    for handler in handlers:
        root_logger.addHandler(handler)

    logger = logging.getLogger("uptimemesh")
    logger.setLevel(log_level)
    logger.handlers.clear()
    for handler in handlers:
        logger.addHandler(handler)
    logger.propagate = False

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True


def get_logger(category: str) -> BoundLogger:
    return BoundLogger(category)
