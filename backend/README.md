# NeuroGuard Backend (FastAPI)

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app:app --reload
# or
python app.py
```

- API base: `http://localhost:8000`
- Routes:
  - `POST /api/chat` → Run security checks and get mock response
  - `GET /api/logs` → Retrieve in-memory logs
  - `GET /api/config` → Available providers

## Example Request

```bash
curl -X POST http://localhost:8000/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"Explain quantum computing","provider":"openai"}'
```

## Response Example

```json
{
  "status": "ok",
  "response": "Secure simulated response",
  "logs": [
    {"layer": "Prompt Injection", "result": "pass"},
    {"layer": "Content Safety", "result": "pass"},
    {"layer": "Anomaly Detection", "result": "pass"},
    {"layer": "LLM Response Validation", "result": "pass"}
  ]
}
```
