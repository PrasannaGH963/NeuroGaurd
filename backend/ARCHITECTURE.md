# NeuroGuard Architecture

## System Overview

NeuroGuard is a multi-layered security middleware that sits between users and LLMs, providing comprehensive protection through adaptive trust scoring, ML-based detection, and immutable audit logging.

## Architecture Diagram

```
┌─────────────┐
│   Client    │
│  (Frontend) │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│                    FastAPI Application                    │
│                      (app.py)                            │
└──────┬────────────────┬──────────────────────────────────┘
       │                │
       ▼                ▼
┌─────────────┐  ┌──────────────┐
│Rate Limiter │  │Trust Scoring │
└─────────────┘  └──────┬───────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│Security      │ │ML Detection   │ │Audit Logger  │
│Layers        │ │(Intent        │ │(Hash Chain)  │
│              │ │Classifier)    │ │              │
└──────────────┘ └──────────────┘ └──────────────┘
```

## Component Architecture

### 1. Application Layer (`app.py`)

**Responsibilities**:
- Request routing and handling
- Component orchestration
- Response formatting
- Error handling

**Key Functions**:
- `chat_endpoint()`: Main chat handler with full security pipeline
- Rate limit checking
- Trust score calculation
- Audit log creation

### 2. Security Layers (`security_layers.py`)

**Five Primary Layers**:

1. **Prompt Injection Detection**
   - Regex pattern matching
   - Instruction override detection
   - System prompt extraction detection

2. **Content Safety**
   - Violence keyword detection
   - Credential request detection
   - Harmful content filtering

3. **Anomaly Detection**
   - Length validation
   - Character analysis (special chars, Unicode)
   - Repetition detection
   - Entropy analysis (Shannon entropy)
   - Token stuffing detection

4. **Context Integrity**
   - Context poisoning detection
   - Coherence validation

5. **Response Validation**
   - PII detection (email, phone, SSN, credit card)
   - Code injection detection
   - URL safety checks
   - Echo attack detection

### 3. Trust Scoring System (`trust_scoring.py`)

**Architecture**:
```
Base Score (50) 
    ↓
+ Layer Results (weighted)
    ↓
+ User History Modifiers
    ↓
= Final Trust Score (0-100)
```

**Layer Weights**:
- Prompt Injection: 25%
- Content Safety: 20%
- Anomaly Detection: 20%
- Context Integrity: 20%
- Response Validation: 15%

**User History Tracking**:
- Maintains last 100 interactions per session
- Clean history (>90% pass) → +5 boost
- Suspicious pattern (>3 alerts in last 10) → -10 penalty

**Trust Levels**:
- Green (80-100): Allow
- Yellow (60-79): Warn
- Orange (40-59): Restrict
- Red (0-39): Block

### 4. ML Detection (`ml_detection.py`)

**Technology Stack**:
- Model: `sentence-transformers/all-MiniLM-L6-v2`
- Embeddings: 384-dimensional vectors
- Similarity: Cosine similarity

**Classification Categories**:
- `benign`: Normal, safe prompts
- `probing`: Information gathering attempts
- `exploitation`: Jailbreak attempts
- `exfiltration`: Data theft attempts

**Attack Pattern Database**:
- 20+ known attack patterns
- 5 prompt injection examples
- 5 jailbreak examples
- 5 exfiltration examples
- 5 benign edge cases

**Similarity Detection**:
- Threshold: 0.75 (configurable)
- Returns top 5 similar attacks
- Cached embeddings for performance

### 5. Audit Logging (`audit_logger.py`)

**Blockchain-Inspired Design**:

```
Log Entry Structure:
┌─────────────────────┐
│ log_id (UUID)       │
│ timestamp           │
│ previous_hash ──────┼───► Points to previous entry
│ session_id          │
│ trust_score         │
│ security_layers     │
│ prompt_hash         │ (SHA-256)
│ response_hash       │ (SHA-256)
│ action_taken        │
│ metadata            │
│ current_hash ───────┼───► Hash of entire entry
└─────────────────────┘
```

**Features**:
- Immutable chain (each entry hashes the previous)
- Cryptographic integrity verification
- SHA-256 hashing
- Tamper detection
- Export capabilities

**Statistics Tracking**:
- Total interactions
- Blocked/Warned/Allowed counts
- Average trust scores
- Security alert counts

### 6. Rate Limiting (`rate_limiter.py`)

**Algorithm**: Sliding Window

**Limits**:
- 20 requests per minute
- 100 requests per hour

**Implementation**:
- Deque-based timestamp tracking
- Automatic cleanup of old entries
- Per-session isolation

### 7. Configuration (`config.py`)

**Configuration Sources** (priority order):
1. Environment variables
2. config.json file
3. Default values

**Configuration Categories**:
- Trust scoring parameters
- Rate limiting thresholds
- Anomaly detection thresholds
- ML model settings
- Audit logging settings

## Data Flow

### Request Flow

```
1. Client Request
   ↓
2. Rate Limit Check
   ↓ (if allowed)
3. Security Layer Checks (parallel)
   ├─ Prompt Injection
   ├─ Content Safety
   ├─ Anomaly Detection
   ├─ Context Integrity
   └─ ML Intent Classification
   ↓
4. Trust Score Calculation
   ├─ Layer Results → Weighted Score
   └─ User History → Modifier
   ↓
5. Action Determination
   ├─ Block (red)
   ├─ Restrict (orange)
   ├─ Warn (yellow)
   └─ Allow (green)
   ↓
6. LLM Call (if allowed)
   ↓
7. Response Validation
   ↓
8. Audit Logging
   ↓
9. Response to Client
```

## Security Design Principles

1. **Defense in Depth**: Multiple independent layers
2. **Fail Secure**: Default to blocking on uncertainty
3. **Adaptive Security**: Trust scoring adapts to user behavior
4. **Auditability**: Immutable logs for forensics
5. **Performance**: Optimized for <500ms response time

## Performance Optimizations

1. **ML Model**: Loaded once at startup
2. **Caching**: LRU cache for embeddings (1000 entries)
3. **Async Operations**: FastAPI async endpoints
4. **Regex Compilation**: Patterns compiled once
5. **In-Memory Storage**: Fast access, configurable limits

## Scalability Considerations

**Current Architecture** (Single Instance):
- In-memory storage
- Synchronous processing
- Suitable for: <10,000 requests/hour

**Future Scalability**:
- Distributed rate limiting (Redis)
- Database-backed audit logs
- Async ML inference queue
- Horizontal scaling with load balancer

## Error Handling

- Rate limit exceeded: 429 status
- Security alert: Detailed error message
- ML model unavailable: Fallback to heuristics
- Chain verification failure: Logged but doesn't block

## Testing Strategy

1. **Unit Tests**: Individual component testing
2. **Integration Tests**: Component interaction testing
3. **Security Tests**: Attack pattern validation
4. **Performance Tests**: Load testing

## Monitoring & Observability

**Metrics Tracked**:
- Request counts by status
- Average trust scores
- Block rate percentage
- ML classification accuracy
- Audit chain integrity

**Logging**:
- Structured logging via audit logger
- Error logging via Python logging
- Performance metrics in metadata

## Configuration Examples

### Trust Score Thresholds
```json
{
  "trust_threshold_green": 80,
  "trust_threshold_yellow": 60,
  "trust_threshold_orange": 40
}
```

### Rate Limits
```json
{
  "rate_limit_per_minute": 20,
  "rate_limit_per_hour": 100
}
```

### ML Settings
```json
{
  "ml_similarity_threshold": 0.75,
  "ml_confidence_threshold": 0.7
}
```

## Future Enhancements

1. **Real LLM Integration**: Connect to actual OpenAI/Gemini/Claude APIs
2. **Machine Learning Pipeline**: Fine-tune model on attack patterns
3. **Distributed Architecture**: Redis for shared state
4. **Advanced Analytics**: Dashboard for security metrics
5. **Custom Rules Engine**: User-defined security policies
6. **Threat Intelligence**: External threat feeds integration

## Dependencies

- **FastAPI**: Web framework
- **sentence-transformers**: ML embeddings
- **scikit-learn**: Similarity calculations
- **numpy**: Numerical operations
- **Pydantic**: Data validation
- **uvicorn**: ASGI server

## License

MIT License

