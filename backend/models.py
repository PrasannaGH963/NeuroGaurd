from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(..., description="User prompt text")
    provider: str = Field(..., description="LLM provider identifier")
    session_id: Optional[str] = Field(None, description="User session identifier (generated if not provided)")


class LayerLog(BaseModel):
    layer: str
    result: str  # "pass" | "alert"
    details: Optional[str] = None


class MLClassification(BaseModel):
    category: str
    confidence: float
    is_malicious: bool
    similar_attacks: Optional[List[Dict[str, Any]]] = None


class ChatResponse(BaseModel):
    status: str  # "ok" | "warning" | "alert" | "blocked"
    response: Optional[str] = None
    reason: Optional[str] = None
    trust_score: int = Field(0, description="Trust score (0-100)")
    trust_level: str = Field("", description="green | yellow | orange | red")
    security_layers: List[LayerLog] = Field(default_factory=list)
    ml_classification: Optional[MLClassification] = None
    session_id: str = ""
    log_id: str = ""
    warnings: Optional[List[str]] = Field(default_factory=list)


class LogsResponse(BaseModel):
    logs: List[Dict[str, Any]]
    total: int = 0
    offset: int = 0
    limit: int = 100


class ConfigResponse(BaseModel):
    providers: List[str]


class AuditStatisticsResponse(BaseModel):
    total_interactions: int
    blocked_count: int
    warned_count: int
    allowed_count: int
    security_alerts: int
    blocked_percentage: float
    average_trust_score: float
    total_logs: int
    chain_verified: bool


class TrustScoreResponse(BaseModel):
    session_id: str
    trust_score: int
    trust_level: str
    total_interactions: int
    passed_count: int
    failed_count: int
    clean_ratio: float
    recent_alerts: int


