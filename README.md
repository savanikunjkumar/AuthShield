# AuthShield

> **Empowering trust through intelligent password defense.**

AuthShield is a production-grade, AI-powered password strength classifier that combines machine-learning-based entropy analysis with real-world breach detection. Unlike rule-based checkers, AuthShield learns from labeled password datasets to identify weak credentials across all pattern classes — dictionary words, repeated sequences, common substitutions — and cross-references results against the Have I Been Pwned (HIBP) breach corpus using a k-anonymity SHA-1 prefix approach that never exposes plaintext passwords to external services.

![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)
![Demo](https://img.shields.io/badge/demo-live-orange?style=flat-square)

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Live Visuals](#live-visuals)
- [API Usage](#api-usage)
- [CLI Usage](#cli-usage)
- [Training the Model](#training-the-model)
- [Security and Privacy](#security-and-privacy)
- [Contributing](#contributing)
- [License](#license)
- [Appendix](#appendix)

---

## Quick Start

### Prerequisites

Python 3.9 or later. A virtual environment is strongly recommended.

**Linux / macOS**

```bash
# Clone the repository
git clone https://github.com/savanikunjkumar/AuthShield.git
cd AuthShield

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Train the model (writes backend/model.pkl)
python backend/train_model.py

# Start the API server (default: http://localhost:5000)
python backend/app.py
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/savanikunjkumar/AuthShield.git
cd AuthShield

python -m venv .venv
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python backend\train_model.py
python backend\app.py
```

---

## Architecture

AuthShield processes every password request through a four-stage pipeline:

```
┌──────────────┐     ┌──────────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  Client/CLI  │────▶│  Feature Extraction  │────▶│  ML Classifier  │────▶│  Breach Check    │
│              │     │  (password_strength) │     │  (model.pkl)    │     │  (HIBP SHA-1)    │
└──────────────┘     └──────────────────────┘     └─────────────────┘     └──────────────────┘
                                                                                    │
                             ◀──────────── JSON Response ────────────────────────────
```

**Stage 1 — Feature Extraction** (`password_strength.py`): Computes a fixed-width numeric vector from the raw password string. No plaintext is stored.

**Stage 2 — ML Classification** (`model.pkl`): A Decision Tree classifier trained on a labelled dataset predicts a strength category (Weak / Medium / Strong) and returns a continuous confidence score.

**Stage 3 — Breach Check**: The password is hashed with SHA-1 locally. Only the first 5 hex characters are sent to the HIBP API (k-anonymity). The response suffix list is matched locally. No plaintext leaves the process boundary.

**Stage 4 — Response**: The API assembles the classification label, numeric score, breach flag, and a human-readable advisory message.

### Model Inputs and Outputs

| Feature | Type | Description |
|---|---|---|
| `length` | int | Total character count |
| `has_lower` | bool | Contains lowercase letters |
| `has_upper` | bool | Contains uppercase letters |
| `has_digits` | bool | Contains numeric characters |
| `has_special` | bool | Contains symbols (`!@#$%^&*...`) |
| `entropy` | float | Shannon entropy estimate (bits) |
| **`strength`** | int | **Output** — 0 = Weak, 1 = Medium, 2 = Strong |

---

## Live Visuals

Generate all three charts by running the scripts in `images/`. Each script works without `dataset.csv` — it synthesizes a representative sample automatically.

```bash
pip install matplotlib seaborn pandas
python images/chart_length_hist.py
python images/chart_strength_dist.py
python images/chart_breach_by_strength.py
```

### Password Length Distribution

Shows how password lengths cluster across the dataset. Most weak credentials concentrate below 8 characters; strong credentials span 12–20+ characters.

![Password Length Distribution](images/length-hist.png)

### Strength Score Distribution

Visualises the class balance across Weak, Medium, and Strong labels. Useful for identifying dataset skew before training.

![Strength Score Distribution](images/strength-dist.png)

### Breach Rate by Strength Category

Illustrates how breach exposure correlates with predicted strength. Weak passwords appear in breach corpora at dramatically higher rates than Medium or Strong credentials.

![Breach Rate by Strength](images/breach-by-strength.png)

---

## API Usage

The REST API is served by `backend/app.py` on `http://localhost:5000` by default.

### `POST /predict`

**Request schema**

```json
{
  "password": "Tr0ub4dor&3"
}
```

**Response schema**

```json
{
  "password": "[REDACTED]",
  "strength": "Strong",
  "strength_score": 2,
  "breached": false,
  "message": "Password meets strong security criteria and has not appeared in known breach datasets."
}
```

| Field | Type | Description |
|---|---|---|
| `strength` | string | Human-readable label: `Weak`, `Medium`, or `Strong` |
| `strength_score` | int | Numeric class: 0, 1, or 2 |
| `breached` | bool | `true` if password hash found in HIBP corpus |
| `message` | string | Actionable advisory for the user |

### cURL

```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"password": "Tr0ub4dor&3"}'
```

### Python `requests`

```python
import requests

response = requests.post(
    "http://localhost:5000/predict",
    json={"password": "Tr0ub4dor&3"},
    timeout=5,
)
data = response.json()
print(f"Strength : {data['strength']} (score={data['strength_score']})")
print(f"Breached : {data['breached']}")
print(f"Advisory : {data['message']}")
```

---

## CLI Usage

`test_password.py` provides an interactive terminal interface for password evaluation.

```bash
python backend/test_password.py
```

**Sample session**

```
┌─────────────────────────────────────┐
│        AuthShield — CLI v1.0        │
└─────────────────────────────────────┘

Enter a password to analyse (q to quit): hunter2

  Strength   : Weak  [score: 0]
  Breached   : YES — found 17,522 times in breach datasets
  Advisory   : This password is extremely common. Replace it immediately.

Enter a password to analyse (q to quit): Tr0ub4dor&3

  Strength   : Strong  [score: 2]
  Breached   : No
  Advisory   : Password meets strong security criteria.
```

**Add a shell alias for convenience**

```bash
# ~/.bashrc or ~/.zshrc
alias authshield="python /path/to/AuthShield/backend/test_password.py"
```

Usage: `authshield check`

---

## Training the Model

```bash
# Train from scratch and overwrite model.pkl
python backend/train_model.py

# Retrain with verbose output and cross-validation report
python backend/train_model.py --cv 5 --verbose
```

`train_model.py` performs the following steps:

1. Loads `backend/dataset.csv` and runs feature extraction via `password_strength.py`.
2. Splits the dataset (80/20 stratified) and runs k-fold cross-validation.
3. Fits a `DecisionTreeClassifier` with optimised depth and impurity parameters.
4. Serialises the fitted model to `backend/model.pkl` using `joblib`.
5. Prints accuracy, precision, recall, F1, and ROC AUC to stdout.

`model.pkl` is automatically loaded by `app.py` at startup. To hot-reload without restarting the server, send a `POST /reload` request (see `backend/README.md` for details).

---

## Security and Privacy

AuthShield is designed to handle passwords without ever persisting or transmitting them in cleartext.

### Core Principles

- **Never log raw passwords.** Only hashed prefixes or opaque request IDs are written to logs.
- **SHA-1 for HIBP k-anonymity only.** Use bcrypt or Argon2 for any credential storage requirement.
- **All external calls use TLS.** Certificate verification is enabled by default; do not disable it.
- **HIBP rate limits.** The implementation uses exponential backoff and locally caches suffix lists to minimise external requests.

### Production Deployment Checklist

- [ ] Serve the API behind TLS (nginx / Caddy reverse proxy).
- [ ] Enable rate limiting on `/predict` (e.g., 60 req/min per IP).
- [ ] Cache HIBP suffix responses in Redis with a TTL of ≥ 24 hours.
- [ ] Store secrets (`HIBP_API_KEY`) in a vault or environment variable; never in source code.
- [ ] Restrict model file permissions (`chmod 600 backend/model.pkl`).
- [ ] Run the API process as a non-root user inside a minimal container image.

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss the proposed change.

1. Fork the repository and create a feature branch: `git checkout -b feat/your-feature`.
2. Write tests for any new functionality (`pytest backend/`).
3. Ensure `flake8` passes with no errors: `flake8 backend/`.
4. Submit a PR with a clear description of the change and its rationale.

For bug reports, please include: Python version, OS, error traceback, and a minimal reproduction.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for full terms.

---

## Appendix

### Glossary

| Term | Definition |
|---|---|
| **Entropy** | A measure of randomness in a password (bits). Higher entropy → harder to guess. |
| **HIBP** | Have I Been Pwned — a public breach-notification service by Troy Hunt. |
| **SHA-1** | A 160-bit cryptographic hash used here solely for HIBP k-anonymity prefix queries. |
| **k-Anonymity** | A privacy model: only the first 5 hex chars of a SHA-1 hash are sent to HIBP; matching is performed locally. |
| **Decision Tree** | A supervised ML model that splits feature space using hierarchical binary rules. |

### Troubleshooting

| Error | Likely Cause | Fix |
|---|---|---|
| `FileNotFoundError: model.pkl` | Model not trained yet | Run `python backend/train_model.py` |
| `HIBP 429 Too Many Requests` | Rate limit exceeded | Enable caching; add exponential backoff |
| `UnicodeDecodeError` on `dataset.csv` | Encoding mismatch | Load with `pd.read_csv(..., encoding='latin-1')` |
| `ModuleNotFoundError` | Dependencies not installed | Run `pip install -r requirements.txt` inside your venv |

