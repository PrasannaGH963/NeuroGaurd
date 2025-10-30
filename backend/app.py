"""
NeuroGuard FastAPI Application with Advanced Security Features.
Integrates trust scoring, ML detection, audit logging, and rate limiting.
"""
import uuid
import time
import logging
import asyncio
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from typing import List, Dict, Any, Optional
import psutil
import os

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
from security_layers import mock_llm_call
from trust_scoring import TrustScoreEngine
from ml_detection import IntentClassifier
from audit_logger import AuditLogger
from rate_limiter import RateLimiter
from async_security_layers import run_all_security_checks, check_llm_response_async
from llm_providers import generate_llm_response, is_llm_configured

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
async def chat_endpoint(payload: ChatRequest) -> ChatResponse:
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
    
    # Run ALL security checks in parallel (async)
    checks_start = time.time()
    security_results = await run_all_security_checks(prompt, intent_classifier)
    checks_duration = (time.time() - checks_start) * 1000

    checks_log: List[Dict[str, Any]] = []
    layer_results: Dict[str, bool] = {}
    ml_metadata = None
    ml_classification = None

    for layer_name, result in security_results.items():
        if layer_name == 'ml_intent':
            passed, reason, ml_metadata = result
            checks_log.append({"layer": "ML Intent Classification", "result": "pass" if passed else "alert", "details": reason})
            layer_results['ml_intent'] = passed
        else:
            passed, reason = result
            display_names = {
                'prompt_injection': 'Prompt Injection',
                'content_safety': 'Content Safety',
                'anomaly_detection': 'Anomaly Detection',
                'context_integrity': 'Context Integrity',
            }
            checks_log.append({"layer": display_names.get(layer_name, layer_name), "result": "pass" if passed else "alert", "details": reason})
            layer_results[layer_name] = passed

    # ML classification for API response
    if ml_metadata:
        similar = ml_metadata.get('similar_attacks')
        if isinstance(similar, list):
            normalized = []
            for item in similar:
                if isinstance(item, tuple) and len(item) == 3:
                    normalized.append({'category': item[0], 'similarity': item[1], 'pattern': item[2]})
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
        
        logger.info(f"Security checks: {checks_duration:.2f}ms (blocked)")
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
        try:
            if is_llm_configured(provider):
                # Use real LLM if API key/configured
                response_text = await generate_llm_response(prompt, provider, timeout=30)
            else:
                # Fallback to mock
                response_text = await asyncio.to_thread(mock_llm_call, prompt=prompt, provider=provider)
        except Exception as llm_exc:
            logger.error(f"LLM generation error: {llm_exc}")
            status = "blocked"
            reason = f"LLM generation failed: {str(llm_exc)}"
            response_text = None
        # Validate
        if response_text and status != "blocked":
            resp_ok, resp_reason = await check_llm_response_async(response_text, original_prompt=prompt)
            checks_log.append({"layer": "LLM Response Validation", "result": "pass" if resp_ok else "alert", "details": resp_reason})
            layer_results['response_validation'] = resp_ok
            if not resp_ok:
                status = "blocked"
                reason = f"Response validation failed: {resp_reason}"
                response_text = None
                trust_engine.update_history(session_id, False)
            else:
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
    
    logger.info(f"Security checks: {checks_duration:.2f}ms | Total latency: {latency_ms}ms | TS: {trust_score}/{trust_level} | Status: {status}")
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


@app.get("/api/stats/performance")
async def get_performance_stats():
    """Get comprehensive performance statistics for local monitoring."""
    try:
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        return {
            'system': {
                'memory_mb': round(memory_info.rss / 1024 / 1024, 2),
                'cpu_percent': process.cpu_percent(interval=0.1),
                'threads': process.num_threads(),
                'uptime_seconds': int(time.time() - process.create_time())
            },
            'ml_classifier': intent_classifier.get_cache_stats() if hasattr(intent_classifier, 'get_cache_stats') else {},
            'rate_limiter': rate_limiter.get_memory_stats(),
            'trust_engine': {
                'active_sessions': len(trust_engine.user_history),
                'total_interactions': sum(len(history) for history in trust_engine.user_history.values()),
            },
            'audit_logger': audit_logger.get_statistics(),
        }
    except Exception as e:
        logging.error(f"Error getting performance stats: {e}")
        return {'error': str(e)}

@app.get("/api/stats/summary")
async def get_stats_summary():
    """Get quick summary statistics for dashboard."""
    audit_stats = audit_logger.get_statistics()
    return {
        'total_requests': audit_stats['total_interactions'],
        'blocked_requests': audit_stats['blocked_count'],
        'blocked_percentage': audit_stats['blocked_percentage'],
        'average_trust_score': audit_stats['average_trust_score'],
        'active_sessions': len(trust_engine.user_history),
        'cache_hit_rate': intent_classifier.get_cache_stats().get('hit_rate_percent', 0) if hasattr(intent_classifier, 'get_cache_stats') else 0
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Simple HTML dashboard for live monitoring."""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NeuroGuard Dashboard</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0; padding: 20px;
                background: linear-gradient(135deg, #232526 0%, #5e72eb 100%);
                color: #fff;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 { text-align: center; font-size: 2.2em; margin-bottom: 36px; text-shadow: 2px 2px #2222; }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 24px; margin-bottom: 32px;
            }
            .stat-card {
                background: rgba(255,255,255,0.08);
                border-radius: 14px;
                padding: 28px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.09);
                border: 1.5px solid rgba(255,255,255,0.08);
            }
            .stat-card h3 { margin: 0 0 14px 0; font-size: 1em; opacity: 0.9; }
            .stat-value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
            .stat-label { font-size: 1em; opacity: 0.7; }
            .status-good { color: #4ade80; }
            .status-warning { color: #fbbf24; }
            .status-bad { color: #f87171; }
            .refresh-info { text-align: center; opacity: 0.7; margin-top: 14px; }
            .detail-section { background: rgba(255,255,255,0.09); border-radius: 14px; padding: 22px; margin-top: 20px; border: 1.5px solid rgba(255,255,255,0.15); }
            .detail-section h2 { margin: 0 0 14px 0; }
            .detail-item { display: flex; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid rgba(255,255,255,0.09); }
            .detail-item:last-child { border-bottom: none; }
        </style>
    </head>
    <body>
    <div class="container">
        <h1>🛡️ NeuroGuard Security Dashboard</h1>
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Requests</h3>
                <div class="stat-value" id="total-requests">-</div>
                <div class="stat-label">Processed</div>
            </div>
            <div class="stat-card">
                <h3>Blocked Rate</h3>
                <div class="stat-value" id="blocked-rate">-</div>
                <div class="stat-label">Percentage</div>
            </div>
            <div class="stat-card">
                <h3>Avg Trust Score</h3>
                <div class="stat-value" id="trust-score">-</div>
                <div class="stat-label">0-100 Scale</div>
            </div>
            <div class="stat-card">
                <h3>Active Sessions</h3>
                <div class="stat-value" id="active-sessions">-</div>
                <div class="stat-label">Currently Active</div>
            </div>
            <div class="stat-card">
                <h3>Cache Hit Rate</h3>
                <div class="stat-value" id="cache-hit">-</div>
                <div class="stat-label">ML Cache Efficiency</div>
            </div>
            <div class="stat-card">
                <h3>Memory Usage</h3>
                <div class="stat-value" id="memory-usage">-</div>
                <div class="stat-label">MB</div>
            </div>
        </div>
        <div class="detail-section">
            <h2>System Details</h2>
            <div id="system-details"></div>
        </div>
        <div class="refresh-info">
            Auto-refreshing every 2 seconds | Last update: <span id="last-update">-</span>
        </div>
    </div>
    <script>
        async function updateDashboard() {
            try {
                const summaryRes = await fetch('/api/stats/summary');
                const summary = await summaryRes.json();
                const perfRes = await fetch('/api/stats/performance');
                const perf = await perfRes.json();
                document.getElementById('total-requests').textContent = summary.total_requests;
                const blockedRate = summary.blocked_percentage;
                const blockedElem = document.getElementById('blocked-rate');
                blockedElem.textContent = blockedRate.toFixed(1) + '%';
                blockedElem.className = 'stat-value ' + (blockedRate < 5 ? 'status-good' : blockedRate < 15 ? 'status-warning' : 'status-bad');
                const trustScore = summary.average_trust_score;
                const trustElem = document.getElementById('trust-score');
                trustElem.textContent = trustScore.toFixed(0);
                trustElem.className = 'stat-value ' + (trustScore >= 80 ? 'status-good' : trustScore >= 60 ? 'status-warning' : 'status-bad');
                document.getElementById('active-sessions').textContent = summary.active_sessions;
                document.getElementById('cache-hit').textContent = summary.cache_hit_rate.toFixed(1) + '%';
                document.getElementById('memory-usage').textContent = perf.system?.memory_mb || '-';
                const detailsHtml = `
                    <div class="detail-item"><span>CPU Usage:</span><span>${perf.system?.cpu_percent || 0}%</span></div>
                    <div class="detail-item"><span>Uptime:</span><span>${Math.floor((perf.system?.uptime_seconds || 0) / 60)} minutes</span></div>
                    <div class="detail-item"><span>ML Cache Size:</span><span>${perf.ml_classifier?.cache_size || 0} entries</span></div>
                    <div class="detail-item"><span>Rate Limiter Sessions:</span><span>${perf.rate_limiter?.total_sessions || 0}</span></div>
                    <div class="detail-item"><span>Total Audit Logs:</span><span>${perf.audit_logger?.total_logs || 0}</span></div>
                    <div class="detail-item"><span>Chain Verified:</span><span>${perf.audit_logger?.chain_verified ? '✓ Yes' : '✗ No'}</span></div>
                `;
                document.getElementById('system-details').innerHTML = detailsHtml;
                document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
            } catch (error) { console.error('Error updating dashboard:', error); }
        }
        updateDashboard();
        setInterval(updateDashboard, 2000);
    </script>
    </body></html>''


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
