"""HTTP API for the IEC 60870-5-104 session audit service."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import APP_VERSION
from .audit import AuditError, AuditFrame, audit_frames
from .models import AuditErrorBody, AuditRequest, AuditResponse

app = FastAPI(title="IEC 60870-5-104 Session Audit", version=APP_VERSION)


class RequestError(Exception):
    """Contract violation in the request itself (HTTP 400)."""

    def __init__(self, code: str, message: str, frame_index: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.frame_index = frame_index


@app.exception_handler(RequestError)
async def request_error_handler(_: Request, exc: RequestError) -> JSONResponse:
    body = {"code": exc.code, "message": exc.message}
    if exc.frame_index is not None:
        body["frameIndex"] = exc.frame_index
    return JSONResponse(status_code=400, content={"error": body})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    errors = exc.errors()
    first = errors[0] if errors else {}
    loc = ".".join(str(part) for part in first.get("loc", []))
    message = f"{loc}: {first.get('msg', 'invalid request')}" if loc else "invalid request"
    return JSONResponse(
        status_code=400,
        content={"error": {"code": "INVALID_REQUEST", "message": message}},
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "iec104-session-audit", "version": APP_VERSION}


@app.post("/api/iec104/sessions/audit", response_model=AuditResponse)
def audit_session(req: AuditRequest) -> AuditResponse:
    for index in range(1, len(req.frames)):
        if req.frames[index].capturedAtUs < req.frames[index - 1].capturedAtUs:
            raise RequestError(
                "FRAMES_NOT_ORDERED",
                f"frames[{index}].capturedAtUs is earlier than "
                f"frames[{index - 1}].capturedAtUs",
                frame_index=index,
            )
    audit_input = [
        AuditFrame(direction=frame.direction, apdu_hex=frame.apduHex)
        for frame in req.frames
    ]
    try:
        stats = audit_frames(audit_input, req.maxUnackedWindow)
    except AuditError as exc:
        return AuditResponse(
            verdict="INVALID",
            error=AuditErrorBody(
                code=exc.code, frameIndex=exc.frame_index, message=exc.message
            ),
        )
    return AuditResponse(verdict="VALID", stats=stats)
