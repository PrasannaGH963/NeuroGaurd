# NeuroGuard Backend (FastAPI)

Advanced LLM security middleware with trust scoring, ML detection, and blockchain-inspired audit logging.

## Features

- Multi-layer security (injection, content safety, anomaly/entropy, context, ML intent, response validation)
- Adaptive trust scoring, user history, rate limit
- Blockchain-style audit log
- Async, parallel security checks for speed
- **Optional: Real LLM provider integration for OpenAI, Anthropic (Claude), Gemini (Google AI)**
- Fallback to mock LLM responses for all local/offline development by default

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

**To enable real LLM completions (OPTIONAL):**
```bash
pip install openai anthropic google-generativeai    # only if you want real LLM
export OPENAI_API_KEY=...                            # or ANTHROPIC_API_KEY, GOOGLE_API_KEY
```

## Run

```bash
uvicorn app:app --reload
# or
python app.py
```

- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Dashboard: http://localhost:8000/dashboard (post-Phase 4)

## Real LLM Integration

- NeuroGuard tries to use the real LLM provider if an API key is set in the environment:
    - `OPENAI_API_KEY` for OpenAI (gpt-4)
    - `ANTHROPIC_API_KEY` for Anthropic Claude
    - `GOOGLE_API_KEY` for Gemini (Google AI)
- If the key is missing or the package is not installed, it **auto-falls back to fast, safe, local mock responses**.
- All security checks and logs work the same, LLM just gets smarter.

**Test with real LLM:**
```bash
export OPENAI_API_KEY=your-key
uvicorn app:app --reload
# Try: curl -X POST http://localhost:8000/api/chat -H 'Content-Type: application/json' -d '{"prompt":"What is AI?", "provider":"openai"}'
```

**Test with offline fallback:**
```bash
unset OPENAI_API_KEY
uvicorn app:app --reload
# Response will always be: [Mock response] This is a simulated secure response to...
```

## Endpoints

- `POST /api/chat` - All security checks + LLM (real or mock)
- `GET /api/config` - Available providers
- `GET /api/logs` - Audit logs (paging, filters)
- `GET /api/session/{session_id}/trust` - Trust score, stats
- ...and more, see API docs

## To Test

- Security: Try malicious + benign prompts
- Performance: See logs for latency improvements from async checks
- Real LLM: See difference with/without API key

## Troubleshooting LLM
- If real LLM not working, check `pip install` for correct provider and validate your API key (try with the provider's CLI to confirm credentials)
- All errors and timeouts are logged and safe—system falls back to local mock

## Advanced usage, monitoring, dashboard: see full instructions below (Phase 4/5/6...)
