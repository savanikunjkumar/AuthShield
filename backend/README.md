# AuthShield Backend

The AuthShield backend is a Python-based ML inference pipeline and REST API for password strength classification and breach detection. It encompasses dataset ingestion, feature engineering, model training and serialisation, a Flask HTTP API, an interactive CLI, and integration with the Have I Been Pwned (HIBP) k-anonymity API. This document is the authoritative technical reference for engineers extending, operating, or auditing the backend.

---

## Architecture Overview

```
Client Request
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  app.py  (Flask REST API)                               │
│  ┌─────────────────────────┐  ┌────────────────────┐   │
│  │  /predict (POST)        │  │  /reload (POST)    │   │
│  │  /health  (GET)         │  │  /metrics (GET)    │   │
│  └────────────┬────────────┘  └────────────────────┘   │
└───────────────┼─────────────────────────────────────────┘
                │
                ▼
     password_strength.py
     Feature Extraction Vector
     [length, has_lower, has_upper, has_digits, has_special, entropy]
                │
                ▼
          model.pkl
     DecisionTreeClassifier
     Strength ∈ {0=Weak, 1=Medium, 2=Strong}
                │
                ├──────────────────────────────────┐
                ▼                                  ▼
     HIBP k-Anonymity Check              Local Breach Lookup
     SHA-1 prefix (5 chars) →           (optional sorted file
     suffix match locally               or RocksDB store)
                │
                ▼
     JSON Response → Client
```

### Component Responsibilities

| File | Role |
|---|---|
| `app.py` | Flask application; exposes `/predict`, `/health`, `/reload` endpoints; handles model loading, request validation, and structured logging |
| `password_strength.py` | Feature extraction; computes length, character-class flags, Shannon entropy, and pattern-match flags from raw password string |
| `train_model.py` | Dataset loading, feature engineering, train/test split, cross-validation, hyperparameter search, model serialisation to `model.pkl` |
| `test_password.py` | Interactive CLI; reads passwords from stdin, calls the feature extractor and breach check, and renders ANSI-coloured output |
| `model.pkl` | Serialised `sklearn` `DecisionTreeClassifier`; loaded at API startup via `joblib.load` |
| `dataset.csv` | Labelled password dataset; expected columns: `password` (str), `strength` (int: 0/1/2) |
| `demo.py` | Batch evaluation script; runs a list of sample passwords through the full pipeline and writes a summary CSV |

---

## Dataset and Feature Engineering

### `dataset.csv` Schema

| Column | Type | Values |
|---|---|---|
| `password` | str | Raw password string (plaintext — handle with care) |
| `strength` | int | 0 = Weak, 1 = Medium, 2 = Strong |

Expected minimum size: 1,000 rows with representative class balance. For reproducible experiments, track dataset SHA-256: `sha256sum dataset.csv`.

### Feature Extraction

```python
# backend/password_strength.py (illustrative extract)
import math
import re
import string

def extract_features(password: str) -> dict:
    """Return a fixed-width feature vector for a given password string."""
    lower  = sum(1 for c in password if c.islower())
    upper  = sum(1 for c in password if c.isupper())
    digits = sum(1 for c in password if c.isdigit())
    specials = sum(1 for c in password if c in string.punctuation)

    # Shannon entropy estimate
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(password)
    entropy = -sum((v / n) * math.log2(v / n) for v in freq.values()) if n > 0 else 0.0

    return {
        "length":      n,
        "has_lower":   int(lower > 0),
        "has_upper":   int(upper > 0),
        "has_digits":  int(digits > 0),
        "has_special": int(specials > 0),
        "entropy":     round(entropy, 4),
    }
```

**Extending features.** Recommended additions for higher model accuracy:

- **N-gram character frequency** (bigram/trigram overlap with common patterns)
- **Dictionary word flag** (check against a compressed wordlist using a Bloom filter)
- **Repeated sequence detection** (`(.+)\1+` regex match)
- **Keyboard walk detection** (`qwerty`, `12345`, `asdf` prefix match)

**Save processed features for audit and reproducibility:**

```python
import pandas as pd

df = pd.read_csv("dataset.csv", encoding="utf-8")
features = df["password"].apply(extract_features).apply(pd.Series)
features["strength"] = df["strength"]
features.to_parquet("backend/features.parquet", index=False)
```

**Data validation checks** (add as `pytest` unit tests):

- Assert no null values in `password` or `strength`.
- Assert `strength` values are in `{0, 1, 2}`.
- Assert `length >= 1` for all rows.
- Assert entropy > 0 for non-trivial passwords.

---

## Model Training and Evaluation

### Model Choice

The default classifier is `sklearn.tree.DecisionTreeClassifier`. It is interpretable, fast to train, and produces feature importances that are auditable by security teams. For production deployments with larger datasets:

| Model | When to prefer |
|---|---|
| `DecisionTreeClassifier` | Small datasets (<50 k rows); interpretability required |
| `RandomForestClassifier` | Medium datasets; higher accuracy; accepts feature noise |
| `XGBClassifier` | Large datasets; best accuracy; requires `xgboost` dependency |

### Full Training Recipe

```python
# backend/train_model.py (canonical version)
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report
from password_strength import extract_features

RANDOM_SEED = 42
MODEL_PATH  = "backend/model.pkl"

df = pd.read_csv("backend/dataset.csv", encoding="utf-8")
X  = df["password"].apply(extract_features).apply(pd.Series)
y  = df["strength"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=RANDOM_SEED
)

model = DecisionTreeClassifier(
    max_depth=10,
    min_samples_split=5,
    class_weight="balanced",
    random_state=RANDOM_SEED,
)

# k-fold cross-validation
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
cv_results = cross_validate(
    model, X_train, y_train, cv=cv,
    scoring=["accuracy", "f1_macro", "roc_auc_ovr_weighted"],
    return_train_score=True,
)
print("CV accuracy :", cv_results["test_accuracy"].mean().round(4))
print("CV F1-macro :", cv_results["test_f1_macro"].mean().round(4))

model.fit(X_train, y_train)
print(classification_report(y_test, model.predict(X_test)))

# Feature importances
importances = pd.Series(model.feature_importances_, index=X.columns)
importances.sort_values(ascending=False).to_csv(
    "backend/feature_importances.csv", header=["importance"]
)

joblib.dump(model, MODEL_PATH)
print(f"Model saved → {MODEL_PATH}")
```

**Run training:**

```bash
cd AuthShield
python backend/train_model.py
```

**Reproducibility:** Pin all dependency versions in `requirements.txt`. Record the dataset SHA-256 and Python version in `backend/experiments/run_<timestamp>.json`. Set `PYTHONHASHSEED=0` in the environment for deterministic hashing.

---

## Breach Check Integration

### HIBP k-Anonymity

```python
import hashlib
import requests
import time

def check_hibp(password: str, retries: int = 3) -> int:
    """
    Returns the number of times `password` appears in HIBP breach corpus.
    Sends only the first 5 hex chars of the SHA-1 hash (k-anonymity).
    Never sends the plaintext password or the full hash to the external service.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    for attempt in range(retries):
        try:
            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
                timeout=5,
            )
            resp.raise_for_status()
            break
        except requests.RequestException:
            if attempt == retries - 1:
                return -1   # -1 signals breach check unavailable
            time.sleep(2 ** attempt)

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0
```

**Caching.** Wrap `check_hibp` with a Redis-backed LRU cache keyed on the SHA-1 prefix (not the password). Set TTL to 86400 seconds. This eliminates redundant external calls for common password patterns.

### Local Breach Dataset (Air-gapped Environments)

Store SHA-1 hashes of known-breached passwords in a sorted flat file. Use binary search for O(log n) lookup:

```python
import bisect

def load_local_breach_hashes(path: str) -> list:
    with open(path, "r") as f:
        return sorted(line.strip().upper() for line in f)

def check_local(password: str, hashes: list) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    idx  = bisect.bisect_left(hashes, sha1)
    return idx < len(hashes) and hashes[idx] == sha1
```

For datasets > 10 M entries, replace the sorted list with RocksDB (`rocksdb` Python binding) for sub-millisecond lookups without loading the full set into memory.

---

## API Internals and Examples

### `app.py` Structure

```python
from flask import Flask, request, jsonify
import joblib
import os

app   = Flask(__name__)
MODEL = joblib.load(os.getenv("MODEL_PATH", "backend/model.pkl"))

STRENGTH_LABELS = {0: "Weak", 1: "Medium", 2: "Strong"}

@app.route("/predict", methods=["POST"])
def predict():
    body = request.get_json(force=True)
    if not body or "password" not in body:
        return jsonify({"error": "Missing 'password' field"}), 400

    password = body["password"]
    if len(password) > 128:
        return jsonify({"error": "Password exceeds maximum length"}), 400

    from password_strength import extract_features
    import pandas as pd
    features = pd.DataFrame([extract_features(password)])
    score    = int(MODEL.predict(features)[0])
    breached = check_hibp(password)

    return jsonify({
        "strength":       STRENGTH_LABELS[score],
        "strength_score": score,
        "breached":       breached > 0,
        "breach_count":   breached,
        "message":        build_advisory(score, breached),
    })

@app.route("/reload", methods=["POST"])
def reload_model():
    """Hot-reload model.pkl without restarting the server."""
    global MODEL
    MODEL = joblib.load(os.getenv("MODEL_PATH", "backend/model.pkl"))
    return jsonify({"status": "model reloaded"})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})
```

**Structured request logging** — log only the hashed prefix, never the raw password:

```python
import logging, hashlib, uuid

def log_request(password: str):
    prefix = hashlib.sha1(password.encode()).hexdigest()[:8]
    logging.info({
        "request_id":   str(uuid.uuid4()),
        "password_hint": prefix,   # 8-char SHA-1 prefix, not plaintext
        "timestamp":    time.time(),
    })
```

---

## CLI Tooling

```bash
python backend/test_password.py
```

**Sample ANSI output:**

```
┌──────────────────────────────────────────┐
│  AuthShield CLI  │  Type 'q' to exit     │
└──────────────────────────────────────────┘

Password: hunter2
  [WEAK]    Score: 0  |  Breached: YES (17,522×)
  Advisory: Replace immediately — appears in common breach datasets.

Password: X#9mK!vL2@qP
  [STRONG]  Score: 2  |  Breached: No
  Advisory: Meets strong security criteria.
```

**Install as CLI entrypoint** via `pyproject.toml`:

```toml
[project.scripts]
authshield = "backend.test_password:main"
```

After `pip install -e .`, run: `authshield check`

---

## Visualization and Demo Scripts

`demo.py` runs a batch of representative passwords through the full pipeline and writes a privacy-safe summary:

```python
# Output columns: password_hash_prefix, strength_score, breached_flag
import hashlib, csv
from password_strength import extract_features

samples = ["hunter2", "P@ssw0rd!", "correct-horse-battery-staple", "X#9mK!vL2@qP"]
with open("backend/demo_output.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["hash_prefix", "strength_score", "breached"])
    for pw in samples:
        feats  = extract_features(pw)
        score  = int(MODEL.predict(pd.DataFrame([feats]))[0])
        prefix = hashlib.sha1(pw.encode()).hexdigest()[:8]
        writer.writerow([prefix, score, check_hibp(pw) > 0])
```

Chart scripts live in `images/`. Run them after training to regenerate `length-hist.png`, `strength-dist.png`, and `breach-by-strength.png` for README embedding.

---

## Security and Privacy Controls

**Mandatory controls:**

- [ ] Never write `password` to any log sink — use the `log_request()` pattern above.
- [ ] Hash with SHA-1 only for HIBP prefix queries. Use bcrypt (`bcrypt.hashpw`) or Argon2 (`argon2-cffi`) for any storage need.
- [ ] All outbound HTTP calls must use `verify=True` (default). Disabling TLS cert verification is prohibited.
- [ ] Apply rate limiting to `/predict`: 60 req/min/IP minimum. Use Flask-Limiter or an upstream proxy rule.
- [ ] Validate input size: reject passwords longer than 128 characters to prevent DoS via entropy calculation.
- [ ] Secrets in environment variables only. Never commit API keys.

**Environment variables:**

```dotenv
HIBP_API_KEY=your_key_here
AUTHSHIELD_ENV=development
MODEL_PATH=./backend/model.pkl
LOG_LEVEL=INFO
REDIS_URL=redis://localhost:6379/0
```

---

## Testing, CI, and Reproducible Experiments

### Unit Tests

```bash
pytest backend/ -v --tb=short
```

**Sample test — entropy:**

```python
# backend/test_password.py (unit test section)
import math
from password_strength import extract_features

def test_entropy_increases_with_complexity():
    weak   = extract_features("aaaaaa")["entropy"]
    strong = extract_features("X#9mK!vL2@qP")["entropy"]
    assert strong > weak

def test_breach_check_returns_int():
    from app import check_hibp
    result = check_hibp("hunter2")
    assert isinstance(result, int) and result >= 0
```

### GitHub Actions CI Outline

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r requirements.txt
      - run: flake8 backend/ --max-line-length=100
      - run: python backend/train_model.py
      - run: pytest backend/ -v
```

### Reproducible Experiment Recipe

```bash
# Pin environment
pip freeze > backend/experiments/requirements_locked.txt
export PYTHONHASHSEED=0
export RANDOM_SEED=42

# Run cross-validation and save results
python backend/train_model.py --save-results backend/experiments/run_$(date +%Y%m%d).json

# Record dataset fingerprint
sha256sum backend/dataset.csv >> backend/experiments/dataset_checksums.txt
```

---

## Deployment and Devcontainer

### Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
RUN python backend/train_model.py
EXPOSE 5000
CMD ["python", "backend/app.py"]
```

### docker-compose.yml

```yaml
version: "3.9"
services:
  api:
    build: .
    ports: ["5000:5000"]
    environment:
      - MODEL_PATH=/app/backend/model.pkl
      - HIBP_API_KEY=${HIBP_API_KEY}
      - REDIS_URL=redis://cache:6379/0
    depends_on: [cache]
  cache:
    image: redis:7-alpine
    ports: ["6379:6379"]
```

### Devcontainer

`.devcontainer/devcontainer.json` provides a reproducible VS Code development environment. Recommended extensions: `ms-python.python`, `ms-python.flake8`, `ms-toolsai.jupyter`, `redhat.vscode-yaml`.

---

## Observability and Monitoring

Export the following Prometheus metrics from `app.py`:

| Metric Name | Type | Description |
|---|---|---|
| `authshield_predict_latency_seconds` | Histogram | End-to-end `/predict` latency |
| `authshield_breach_check_latency_seconds` | Histogram | HIBP call latency |
| `authshield_breach_rate` | Gauge | Rolling fraction of requests with `breached=true` |
| `authshield_strength_score_distribution` | Counter | Per-label (0/1/2) prediction counts |
| `authshield_model_confidence` | Histogram | Max class probability from `predict_proba` |

Structured log schema (JSON lines):

```json
{
  "ts": 1718000000.123,
  "request_id": "b4f2...",
  "password_hint": "5baa61",
  "strength_score": 0,
  "breached": true,
  "latency_ms": 43.2
}
```

---

## Contributing and License

Branch naming: `feat/<description>`, `fix/<issue-id>`, `chore/<description>`. Every PR must include updated tests and pass CI. For security vulnerability reports, use GitHub Security Advisories — do not open a public issue.

Distributed under the **MIT License**. See [LICENSE](../LICENSE) for terms. Attribution: Kunj Saraswat — [savanikunjkumar](https://github.com/savanikunjkumar).

---

## Appendix

### Glossary

| Term | Definition |
|---|---|
| **Entropy** | Shannon entropy H = −Σ p(x) log₂ p(x). Measures randomness in bits; higher is harder to guess. |
| **k-Anonymity** | Privacy model: HIBP returns all suffix hashes matching a prefix, so no single hash is transmitted. |
| **SHA-1** | 160-bit hash function; used only for HIBP prefix query. Cryptographically weak for storage — use bcrypt/Argon2 instead. |
| **Decision Tree** | Supervised model producing nested binary splits on feature values; inherently interpretable. |
| **Cross-Validation** | k-fold evaluation that estimates generalisation error by rotating train/validation splits. |

### Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `FileNotFoundError: model.pkl` | Training not run | `python backend/train_model.py` |
| `HIBP HTTP 429` | Rate limit hit | Add `time.sleep(1.6)` between calls; enable Redis caching |
| `UnicodeDecodeError` on `dataset.csv` | Non-UTF-8 encoding | `pd.read_csv(..., encoding='latin-1')` |
| `ValueError: Unknown label type` | `strength` column contains floats | `df['strength'] = df['strength'].astype(int)` |
| `ConnectionRefusedError` on Redis | Cache service not running | `docker compose up cache` or disable caching in dev |
