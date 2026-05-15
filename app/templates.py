from __future__ import annotations

from importlib.resources import files
from typing import Any, Mapping

from fastapi import Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates


def _template_directory() -> str:
    return str(files("app").joinpath("templates"))


templates = Jinja2Templates(directory=_template_directory())


def render_template(
    request: Request,
    template_name: str,
    context: Mapping[str, Any],
    *,
    status_code: int = 200,
) -> Response:
    payload = dict(context)
    payload.setdefault("request", request)
    return templates.TemplateResponse(
        request,
        template_name,
        payload,
        status_code=status_code,
    )
