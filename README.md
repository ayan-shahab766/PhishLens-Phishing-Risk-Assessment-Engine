# PhishLens — Phishing Risk Assessment Engine

PhishLens is a defensive email-security prototype that combines a machine-learning text classifier with deterministic security analysis. Rather than returning only a binary verdict, it creates an explainable phishing-risk assessment from message text, email headers, sender alignment, authentication results, URLs, attachment metadata, and social-engineering language.

> **Safety model:** PhishLens never opens submitted links or executes attachments. It analyzes only the message content supplied to the local API.

## Threat-triage pipeline

```text
Pasted email or RFC-822 text
        │
        ├── TF-IDF + Gradient Boosting text classifier
        ├── Header and sender-alignment inspection
        ├── SPF / DKIM / DMARC result detection
        ├── URL and domain-obfuscation feature extraction
        └── Attachment metadata and social-engineering signals
                         │
                         ▼
        Explainable 0–100 risk score + severity + response guidance
                         │
                         ▼
             Local audit metadata and analyst feedback
```

## Core capabilities

- **Hybrid risk scoring:** combines model phishing probability with deterministic, inspectable security signals.
- **Header intelligence:** exposes sender/reply-to/return-path misalignment and failed SPF, DKIM, or DMARC outcomes when present.
- **Safe URL inspection:** detects direct-IP links, punycode, shortened links, high-risk TLDs, and obfuscation patterns without visiting a link.
- **Content and attachment indicators:** identifies account-pressure, credential, payment-transfer, impersonation, and risky attachment-extension signals.
- **Severity-aware triage:** reports `low`, `medium`, `high`, or `critical` severity with practical next steps.
- **Analyst feedback loop:** lets a reviewer mark an assessment as confirmed phishing, confirmed safe, or needing review.
- **Privacy-conscious history:** message text is processed in memory. The local SQLite history retains only a SHA-256 hash, scores, evidence, timestamps, and feedback.
- **Operational readiness:** health endpoint, documented API, CORS allow-list, request-size validation, pinned dependencies, Docker support, and baseline tests.

## Technology stack

- Python 3.10+
- FastAPI + Uvicorn
- scikit-learn `TfidfVectorizer` + `GradientBoostingClassifier`
- pandas for dataset preparation
- SQLite for local audit metadata
- Vanilla HTML/CSS/JavaScript analyst console

## Run locally

Create and activate a virtual environment, then install dependencies:

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The repository includes existing trained model artifacts. To retrain them from the dataset and produce evaluation metadata:

```bash
python train_model.py
```

Start the API from the backend directory:

```bash
cd backend
uvicorn app:app --reload
```

Serve the `frontend` directory using any static web server (for example VS Code Live Server) at `http://127.0.0.1:5500`, then open `index.html`. The API defaults to `http://127.0.0.1:8000`.

To permit a different frontend origin, set `PHISHLENS_ALLOWED_ORIGINS` from `.env.example` in your environment before starting Uvicorn.

Run the signal tests:

```bash
cd backend
python -m unittest discover -s tests
```

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness and model-load check |
| `POST` | `/api/v1/analyze` | Analyze email/RFC-822 text |
| `GET` | `/api/v1/history` | Retrieve local analysis metadata |
| `POST` | `/api/v1/analyses/{id}/feedback` | Add an analyst outcome |

Example request:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"email":"From: alerts@example.example\nSubject: Verify account\n\nSign in immediately."}'
```

## Docker

```bash
docker build -t phishlens .
docker run --rm -p 8000:8000 phishlens
```

## Evaluation and limitations

`train_model.py` cleans the source CSV's unused extra column by reading only `Email Text` and `Email Type`. It uses a stratified split and emits accuracy, precision, recall, F1, and ROC-AUC; accuracy alone is not a sufficient phishing-detection metric.

This is a portfolio and learning project, not a replacement for a secure email gateway, malware sandbox, threat-intelligence platform, or human security team. Detection results are probabilistic and must be independently verified. Do not submit sensitive production emails to a shared or untrusted deployment.

## Upstream attribution and reuse

PhishLens was substantially extended from the public **Phishing Email Detection System** by Saad Nadeem, Saad Habib, Abdul Basit, Talha Rauf, and Sultan-ul-Arfeen. The original repository did not include a license file at the time this derivative was created. Obtain permission from the original authors before publishing or redistributing this derivative publicly, and retain appropriate attribution.
