# NeuroGuard Backend (FastAPI)

Advanced LLM security middleware with trust scoring, ML detection, and blockchain-inspired audit logging.

## Features

- **Multi-Layer Security Checks**: Prompt injection, content safety, anomaly detection, context integrity, and response validation
- **Trust Scoring System**: Adaptive trust scoring based on security layer results and user history
- **ML-Based Intent Classification**: Uses sentence transformers to detect malicious intents
- **Rate Limiting**: Sliding window rate limiting per session
- **Audit Logging**: Immutable, blockchain-inspired audit logs with cryptographic integrity
- **Configuration Management**: Flexible configuration via JSON or environment variables

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Note**: First run will download the ML model (~80MB). This happens automatically.

## Run

```bash
uvicorn app:app --reload
# or
python app.py
```

- API base: `http://localhost:8000`
- API docs: `http://localhost:8000/docs` (Swagger UI)
- ReDoc: `http://localhost:8000/redoc`

## API Endpoints

### Core Endpoints

- `POST /api/chat` → Main chat endpoint with comprehensive security checks
- `GET /api/config` → Get available LLM providers
- `GET /api/logs` → Retrieve audit logs (with filtering and pagination)

### Audit & Statistics

- `GET /api/audit/statistics` → Get security statistics
- `GET /api/audit/verify` → Verify audit log chain integrity
- `POST /api/audit/export` → Export audit logs as JSON

### Session Management

- `GET /api/session/{session_id}/trust` → Get trust score for a session
- `GET /api/rate-limit/status?session_id={id}` → Get rate limit status

## Example Request

```bash
curl -X POST http://localhost:8000/api/chat \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "Explain quantum computing",
    "provider": "openai",
    "session_id": "user123"
  }'
```

## Enhanced Response Example

```json
{
  "status": "ok",
  "response": "Secure simulated response",
  "trust_score": 85,
  "trust_level": "green",
  "security_layers": [
    {
      "layer": "Prompt Injection",
      "result": "pass",
      "details": "OK"
    },
    {
      "layer": "Content Safety",
      "result": "pass",
      "details": "OK"
    },
    {
      "layer": "Anomaly Detection",
      "result": "pass",
      "details": "OK"
    },
    {
      "layer": "Context Integrity",
      "result": "pass",
      "details": "OK"
    },
    {
      "layer": "ML Intent Classification",
      "result": "pass",
      "details": "OK"
    },
    {
      "layer": "LLM Response Validation",
      "result": "pass",
      "details": "OK"
    }
  ],
  "ml_classification": {
    "category": "benign",
    "confidence": 0.92,
    "is_malicious": false
  },
  "session_id": "user123",
  "log_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Trust Score Levels

- **Green (80-100)**: Full access, all security checks passed
- **Yellow (60-79)**: Monitored access with warnings
- **Orange (40-59)**: Restricted access requiring confirmation
- **Red (0-39)**: Blocked, request denied

## Configuration

Configuration can be modified via:

1. **config.json** - Edit JSON file directly
2. **Environment Variables** - Override specific settings:
   ```bash
   export TRUST_BASE_SCORE=50
   export RATE_LIMIT_PER_MINUTE=20
   export ML_SIMILARITY_THRESHOLD=0.75
   ```

See `config.py` for all available configuration options.

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test file
pytest tests/test_security_layers.py -v
```

## Security Features

### Prompt Injection Detection
- Pattern-based detection for instruction override attempts
- System prompt extraction detection
- Safety bypass attempts

### Content Safety
- Violence and harmful content detection
- Credential request detection (API keys, passwords, tokens)

### Anomaly Detection
- Length validation
- Special character ratio analysis
- Unicode/non-ASCII detection
- Repetition pattern detection
- Shannon entropy analysis
- Token stuffing detection

### Response Validation
- PII detection (email, phone, SSN, credit card)
- Code injection detection (SQL, JavaScript, shell commands)
- URL safety checks
- Echo attack detection
- JSON structure validation

### ML Intent Classification
- Uses `sentence-transformers/all-MiniLM-L6-v2`
- Categories: benign, probing, exploitation, exfiltration
- Similarity matching against known attack patterns

## Architecture

See `ARCHITECTURE.md` for detailed system architecture documentation.

## Performance

- Average request processing: <500ms
- ML model loads once at startup
- Efficient caching for repeated computations
- In-memory storage (configurable limits)

## License

MIT License
