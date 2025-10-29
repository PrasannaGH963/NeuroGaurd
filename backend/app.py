"""
NeuroGuard FastAPI Application with Advanced Security Features.
Integrates trust scoring, ML detection, audit logging, and rate limiting.
"""
import uuid
import time
import logging
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import List, Dict, Any, Optional

from models import (
    ChatRequest,
    ChatResponse,
    LogsResponse,
    ConfigResponse,
    AuditStatisticsResponse,
    TrustScoreResponse,
    LayerLog,
    MLClassification,
)
from security_layers import (
    check_prompt_injection,
    check_content_safety,
    check_prompt_anomaly,
    check_context_integrity,
    check_llm_response,
    mock_llm_call,
)
from trust_scoring import TrustScoreEngine
from ml_detection import IntentClassifier, check_ml_intent
from audit_logger import AuditLogger
from rate_limiter import RateLimiter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NeuroGuard Backend",
    version="2.0.0",
    description="Advanced LLM security middleware with trust scoring, ML detection, and audit logging"
)

# Allow local dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize global components
trust_engine = TrustScoreEngine()
intent_classifier = IntentClassifier()
audit_logger = AuditLogger()
rate_limiter = RateLimiter()

logger.info("NeuroGuard initialized with all security components")


@app.post("/api/chat", response_model=ChatResponse)
def chat_endpoint(payload: ChatRequest) -> ChatResponse:
    """
    Main chat endpoint with comprehensive security checks.
    """
    start_time = time.time()
    prompt = payload.prompt
    provider = payload.provider
    
    # Generate or use provided session ID
    session_id = payload.session_id or str(uuid.uuid4())
    
    # Check rate limits first
    rate_allowed, rate_message, retry_after = rate_limiter.check_rate_limit(session_id)
    if not rate_allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "message": rate_message,
                "retry_after": retry_after
            }
        )
    
    # Collect security layer results
    checks_log: List[Dict[str, Any]] = []
    layer_results: Dict[str, bool] = {}
    
    # 1) Prompt Injection
    inj_ok, inj_reason = check_prompt_injection(prompt)
    checks_log.append({
        "layer": "Prompt Injection",
        "result": "pass" if inj_ok else "alert",
        "details": inj_reason
    })
    layer_results['prompt_injection'] = inj_ok
    
    # 2) Content Safety
    safe_ok, safe_reason = check_content_safety(prompt)
    checks_log.append({
        "layer": "Content Safety",
        "result": "pass" if safe_ok else "alert",
        "details": safe_reason
    })
    layer_results['content_safety'] = safe_ok
    
    # 3) Prompt Anomaly Detection
    anom_ok, anom_reason = check_prompt_anomaly(prompt)
    checks_log.append({
        "layer": "Anomaly Detection",
        "result": "pass" if anom_ok else "alert",
        "details": anom_reason
    })
    layer_results['anomaly_detection'] = anom_ok
    
    # 4) Context Integrity
    ctx_ok, ctx_reason = check_context_integrity(prompt)
    checks_log.append({
        "layer": "Context Integrity",
        "result": "pass" if ctx_ok else "alert",
        "details": ctx_reason
    })
    layer_results['context_integrity'] = ctx_ok
    
    # 5) ML Intent Classification
    ml_ok, ml_reason, ml_metadata = check_ml_intent(prompt, intent_classifier)
    checks_log.append({
        "layer": "ML Intent Classification",
        "result": "pass" if ml_ok else "alert",
        "details": ml_reason
    })
    layer_results['ml_intent'] = ml_ok
    
    ml_classification = None
    if ml_metadata:
        # Ensure similar_attacks are dicts for pydantic validation
        similar = ml_metadata.get('similar_attacks')
        if isinstance(similar, list):
            normalized = []
            for item in similar:
                if isinstance(item, tuple) and len(item) == 3:
                    normalized.append({
                        'category': item[0],
                        'similarity': item[1],
                        'pattern': item[2]
                    })
                elif isinstance(item, dict):
                    normalized.append(item)
            if normalized:
                ml_metadata['similar_attacks'] = normalized
        ml_classification = MLClassification(
            category=ml_metadata.get('category', 'unknown'),
            confidence=ml_metadata.get('confidence', 0.0),
            is_malicious=ml_metadata.get('is_malicious', False),
            similar_attacks=ml_metadata.get('similar_attacks')
        )
    
    # Calculate trust score
    trust_result = trust_engine.calculate_score(layer_results, session_id)
    trust_score = trust_result['score']
    trust_level = trust_result['level']
    action = trust_result['action']
    
    # Determine response status and action
    warnings: List[str] = []
    response_text: Optional[str] = None
    status: str
    reason: Optional[str] = None
    
    if action == 'block':
        # Red zone - block request
        status = "blocked"
        reason = f"Request blocked due to low trust score ({trust_score}). Security layers triggered."
        
        # Update trust history (failed)
        trust_engine.update_history(session_id, False)
        
        # Log security event
        audit_logger.log_security_event(
            session_id=session_id,
            event_type="security_alert",
            severity="high",
            description=f"Request blocked due to trust score {trust_score}",
            layers=checks_log,
            trust_score=trust_score,
            trust_level=trust_level
        )
        
        return ChatResponse(
            status=status,
            reason=reason,
            trust_score=trust_score,
            trust_level=trust_level,
            security_layers=[LayerLog(**log) for log in checks_log],
            ml_classification=ml_classification,
            session_id=session_id,
            warnings=warnings
        )
    
    elif action == 'restrict':
        # Orange zone - require confirmation
        status = "alert"
        reason = f"Restricted access: Trust score {trust_score} requires additional verification."
        warnings.append("This request requires additional security verification.")
    
    elif action == 'warn':
        # Yellow zone - allow with warning
        status = "warning"
        warnings.append(f"Trust score ({trust_score}) indicates some risk. Proceed with caution.")
    
    else:
        # Green zone - full access
        status = "ok"
    
    # If allowed, process LLM call
    if action in ['allow', 'warn', 'restrict']:
        response_text = mock_llm_call(prompt=prompt, provider=provider)
        
        # Validate LLM response
        resp_ok, resp_reason = check_llm_response(response_text, original_prompt=prompt)
        checks_log.append({
            "layer": "LLM Response Validation",
            "result": "pass" if resp_ok else "alert",
            "details": resp_reason
        })
        layer_results['response_validation'] = resp_ok
        
        if not resp_ok:
            # Response validation failed - block
            status = "blocked"
            reason = f"Response validation failed: {resp_reason}"
            response_text = None
            trust_engine.update_history(session_id, False)
        else:
            # Update trust history (passed)
            trust_engine.update_history(session_id, True)
    
    # Calculate latency
    latency_ms = int((time.time() - start_time) * 1000)
    
    # Log interaction
    log_id = audit_logger.log_interaction(
        session_id=session_id,
        trust_score=trust_score,
        trust_level=trust_level,
        layers=checks_log,
        action=action,
        prompt=prompt,
        response=response_text,
        ml_classification=ml_metadata,
        provider=provider,
        latency_ms=latency_ms
    )
    
    # Build response
    return ChatResponse(
        status=status,
        response=response_text,
        reason=reason,
        trust_score=trust_score,
        trust_level=trust_level,
        security_layers=[LayerLog(**log) for log in checks_log],
        ml_classification=ml_classification,
        session_id=session_id,
        log_id=log_id,
        warnings=warnings if warnings else None
    )


@app.get("/api/logs", response_model=LogsResponse)
def get_logs(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
) -> LogsResponse:
    """Get audit logs with filtering and pagination."""
    logs = audit_logger.get_logs(
        session_id=session_id,
        event_type=event_type,
        limit=limit,
        offset=offset
    )
    return LogsResponse(
        logs=logs,
        total=len(audit_logger.logs),
        offset=offset,
        limit=limit
    )


@app.get("/api/config", response_model=ConfigResponse)
def get_config_endpoint() -> ConfigResponse:
    """Get available LLM providers."""
    return ConfigResponse(providers=["openai", "gemini", "claude"])


@app.get("/api/audit/statistics", response_model=AuditStatisticsResponse)
def get_audit_statistics() -> AuditStatisticsResponse:
    """Get audit log statistics."""
    stats = audit_logger.get_statistics()
    return AuditStatisticsResponse(**stats)


@app.get("/api/audit/verify")
def verify_audit_chain() -> Dict[str, Any]:
    """Verify integrity of audit log chain."""
    is_valid, errors = audit_logger.verify_chain()
    return {
        "valid": is_valid,
        "errors": errors,
        "total_logs": len(audit_logger.logs)
    }


@app.post("/api/audit/export")
def export_audit_logs() -> FileResponse:
    """Export audit logs as JSON file."""
    filepath = audit_logger.export_logs()
    return FileResponse(
        path=filepath,
        filename="neuroguard_audit_logs.json",
        media_type="application/json"
    )


@app.get("/api/session/{session_id}/trust", response_model=TrustScoreResponse)
def get_session_trust(session_id: str) -> TrustScoreResponse:
    """Get trust score and statistics for a session."""
    stats = trust_engine.get_user_stats(session_id)
    
    # Calculate current trust score (need to pass dummy layer results)
    # For display purposes, use history stats
    if stats['total_interactions'] == 0:
        trust_score = 50  # Default
        trust_level = "yellow"
    else:
        clean_ratio = stats['clean_ratio']
        # Rough estimate: clean ratio * 100
        trust_score = int(clean_ratio * 100)
        trust_result = trust_engine._get_trust_level_and_action(trust_score)
        trust_level = trust_result[0]
    
    return TrustScoreResponse(
        session_id=session_id,
        trust_score=trust_score,
        trust_level=trust_level,
        **stats
    )


@app.get("/api/rate-limit/status")
def get_rate_limit_status(session_id: str = Query(..., description="Session ID")) -> Dict[str, Any]:
    """Get current rate limit status for a session."""
    return rate_limiter.get_rate_limit_status(session_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
