from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(..., description="User prompt text")
    provider: str = Field(..., description="LLM provider identifier")


class LayerLog(BaseModel):
    layer: str
    result: str  # "pass" | "alert"


class ChatResponse(BaseModel):
    status: str  # "ok" | "alert"
    response: Optional[str] = None
    reason: Optional[str] = None
    logs: List[LayerLog] = Field(default_factory=list)


class LogsResponse(BaseModel):
    logs: List[Dict[str, Any]]


class ConfigResponse(BaseModel):
    providers: List[str]


