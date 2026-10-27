"""PhishLens API: explainable, local-first phishing risk assessment."""

from __future__ import annotations

import hashlib
import os
import pickle
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analysis import extract_security_signals, recommended_actions, severity_for
from storage import initialize_database, recent_analyses, save_analysis, save_feedback


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"


class EmailInput(BaseModel):
    email: str = Field(min_length=10, max_length=200_000, description="Pasted email content or RFC-822 .eml text")


class FeedbackInput(BaseModel):
    outcome: Literal["confirmed_phishing", "confirmed_safe", "needs_review"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="PhishLens API",
    version="1.0.0",
    description="Explainable email threat triage. URLs are never opened and raw message bodies are not stored.",
    lifespan=lifespan,
)

allowed_origins = [origin.strip() for origin in os.getenv("PHISHLENS_ALLOWED_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
    raise RuntimeError("Missing model artifacts. Run `python train_model.py` before starting the API.")

# Pickle files are loaded solely from local, version-controlled/trusted artifacts.
with MODEL_PATH.open("rb") as model_file:
    model = pickle.load(model_file)
with VECTORIZER_PATH.open("rb") as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)


def _top_model_terms(email_text: str, limit: int = 5) -> list[str]:
    """Return present terms with the largest tree-model feature importance.

    These are explanatory hints, not causal statements about the classification.
    """
    if not hasattr(model, "feature_importances_"):
        return []
    vector = vectorizer.transform([email_text])
    if vector.nnz == 0:
        return []
    names = vectorizer.get_feature_names_out()
    ranked = sorted(
        ((model.feature_importances_[index] * value, names[index]) for index, value in zip(vector.indices, vector.data)),
        reverse=True,
    )
    return [term for score, term in ranked[:limit] if score > 0]


def analyse(email_text: str) -> dict:
    vector = vectorizer.transform([email_text])
    probabilities = model.predict_proba(vector)[0]
    model_phishing_probability = float(probabilities[1]) * 100
    inspection = extract_security_signals(email_text)

    # ML accounts for text semantics; deterministic indicators expose concrete
    # sender, URL, authentication, attachment, and social-engineering evidence.
    risk_score = round(min(100, (model_phishing_probability * 0.65) + (inspection["deterministic_score"] * 0.35)), 1)
    severity = severity_for(risk_score)
    analysis_id = str(uuid.uuid4())
    content_hash = hashlib.sha256(email_text.encode("utf-8")).hexdigest()
    record = {
        "id": analysis_id,
        "content_hash": content_hash,
        "risk_score": risk_score,
        "severity": severity,
        "model_probability": round(model_phishing_probability, 1),
        "signals": inspection["signals"],
    }
    save_analysis(record)

    return {
        "analysis_id": analysis_id,
        "verdict": "likely_phishing" if severity in {"high", "critical"} else "needs_caution" if severity == "medium" else "low_risk",
        "risk_score": risk_score,
        "severity": severity,
        "model": {
            "name": "TF-IDF + Gradient Boosting",
            "phishing_probability": round(model_phishing_probability, 1),
            "top_present_terms": _top_model_terms(email_text),
        },
        "evidence": inspection,
        "recommended_actions": recommended_actions(severity),
        "privacy": "Raw email content is analyzed in memory and is not retained in the local history store.",
        "disclaimer": "This result is advisory. Do not open suspicious links or attachments based on this assessment.",
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "phishlens", "model_loaded": True}


@app.post("/api/v1/analyze")
@app.post("/predict", include_in_schema=False)  # Backward-compatible endpoint for the original UI.
async def predict(email: EmailInput) -> dict:
    return analyse(email.email)


@app.get("/api/v1/history")
async def history(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    return {"items": recent_analyses(limit)}


@app.post("/api/v1/analyses/{analysis_id}/feedback")
async def feedback(analysis_id: str, payload: FeedbackInput) -> dict:
    if not save_feedback(analysis_id, payload.outcome):
        raise HTTPException(status_code=404, detail="Analysis record was not found")
    return {"status": "recorded", "analysis_id": analysis_id, "outcome": payload.outcome}
