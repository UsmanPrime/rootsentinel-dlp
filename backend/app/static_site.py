"""Serve the built single-page frontend from the same origin as the API.

The frontend calls relative ``/api/v1`` URLs with same-origin credentials, so serving it here keeps
one origin: cookies stay SameSite=Strict, Origin and Host checks are unchanged and no CORS exists.

Rules: only GET and HEAD, never anything under ``/api``, no directory listings, no symlink or
parent-directory escapes, and an unknown file-like path is a 404 rather than the HTML shell.
Unknown ``/api`` paths return the API's typed JSON 404. Nothing here is authenticated and
nothing here reads application data.
"""
from pathlib import Path

from fastapi import Request
from starlette.responses import FileResponse


def install_static(app, directory: Path, not_found):
    root = directory.resolve()
    index = root / "index.html"
    if not root.is_dir() or not index.is_file():
        raise RuntimeError("The frontend directory must contain a built index.html")

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def frontend(path: str, request: Request):
        first = path.split("/", 1)[0]
        if first == "api":
            return not_found()
        if "\x00" in path or "\\" in path or any(part.startswith(".") for part in path.split("/")):
            return not_found()
        if path:
            candidate = (root / path)
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, ValueError):
                resolved = None
            if resolved is not None and resolved.is_file() and root in resolved.parents and not candidate.is_symlink():
                return FileResponse(resolved)
            if "." in path.rsplit("/", 1)[-1]:
                return not_found()      # a missing script, style or image must not be answered with HTML
        return FileResponse(index, media_type="text/html")

    return frontend
