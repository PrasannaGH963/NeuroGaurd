from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any

from models import ChatRequest, ChatResponse, LogsResponse, ConfigResponse
from security_layers import (
    check_prompt_injection,
    check_content_safety,
    check_prompt_anomaly,
    check_llm_response,
    mock_llm_call,
    timestamp,
)


app = FastAPI(title="NeuroGuard Backend", version="0.1.0")

# Allow local dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# In-memory logs store. Each entry is a dict with details about checks.
logs_store: List[Dict[str, Any]] = []


@app.post("/api/chat", response_model=ChatResponse)
def chat_endpoint(payload: ChatRequest) -> ChatResponse:
    prompt = payload.prompt
    provider = payload.provider

    checks_log: List[Dict[str, str]] = []

    # 1) Prompt Injection
    inj_ok, inj_reason = check_prompt_injection(prompt)
    checks_log.append({"layer": "Prompt Injection", "result": "pass" if inj_ok else "alert"})
    if not inj_ok:
        logs_store.append({
            "timestamp": timestamp(),
            "provider": provider,
            "prompt": prompt,
            "checks": checks_log,
            "status": "alert",
            "reason": inj_reason,
        })
        return ChatResponse(status="alert", reason=inj_reason, logs=checks_log)

    # 2) Content Safety
    safe_ok, safe_reason = check_content_safety(prompt)
    checks_log.append({"layer": "Content Safety", "result": "pass" if safe_ok else "alert"})
    if not safe_ok:
        logs_store.append({
            "timestamp": timestamp(),
            "provider": provider,
            "prompt": prompt,
            "checks": checks_log,
            "status": "alert",
            "reason": safe_reason,
        })
        return ChatResponse(status="alert", reason=safe_reason, logs=checks_log)

    # 3) Prompt Anomaly
    anom_ok, anom_reason = check_prompt_anomaly(prompt)
    checks_log.append({"layer": "Anomaly Detection", "result": "pass" if anom_ok else "alert"})
    if not anom_ok:
        logs_store.append({
            "timestamp": timestamp(),
            "provider": provider,
            "prompt": prompt,
            "checks": checks_log,
            "status": "alert",
            "reason": anom_reason,
        })
        return ChatResponse(status="alert", reason=anom_reason, logs=checks_log)

    # If all pass, call mock LLM
    response_text = mock_llm_call(prompt=prompt, provider=provider)

    # 4) Validate LLM response
    resp_ok, resp_reason = check_llm_response(response_text)
    checks_log.append({"layer": "LLM Response Validation", "result": "pass" if resp_ok else "alert"})
    if not resp_ok:
        logs_store.append({
            "timestamp": timestamp(),
            "provider": provider,
            "prompt": prompt,
            "checks": checks_log,
            "status": "alert",
            "reason": resp_reason,
        })
        return ChatResponse(status="alert", reason=resp_reason, logs=checks_log)

    # Success
    logs_store.append({
        "timestamp": timestamp(),
        "provider": provider,
        "prompt": prompt,
        "checks": checks_log,
        "status": "ok",
    })
    return ChatResponse(status="ok", response=response_text, logs=checks_log)


@app.get("/api/logs", response_model=LogsResponse)
def get_logs() -> LogsResponse:
    return LogsResponse(logs=logs_store)


@app.get("/api/config", response_model=ConfigResponse)
def get_config() -> ConfigResponse:
    return ConfigResponse(providers=["openai", "gemini", "claude"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)


