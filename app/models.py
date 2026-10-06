"""Request/response schemas for the session audit API."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Direction = Literal["clientToServer", "serverToClient"]

MAX_FRAMES = 5000
MAX_UNACKED_WINDOW = 16383
MAX_APDU_HEX_LEN = 510  # 255 octets


class Frame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capturedAtUs: int = Field(ge=0)
    direction: Direction
    apduHex: str = Field(min_length=1, max_length=MAX_APDU_HEX_LEN)


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    maxUnackedWindow: int = Field(ge=1, le=MAX_UNACKED_WINDOW)
    frames: list[Frame] = Field(min_length=1, max_length=MAX_FRAMES)


class DirectionStats(BaseModel):
    iFrames: int
    unacked: int


class HandshakeCount(BaseModel):
    act: int
    con: int


class AuditStats(BaseModel):
    perDirection: dict[str, DirectionStats]
    handshakes: dict[str, HandshakeCount]


class AuditErrorBody(BaseModel):
    code: str
    frameIndex: int
    message: str


class AuditResponse(BaseModel):
    verdict: Literal["VALID", "INVALID"]
    stats: AuditStats | None = None
    error: AuditErrorBody | None = None
