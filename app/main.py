
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from src.data.database import (
    get_analysis,
    get_history,
    get_statistics,
    save_analysis,
)
from src.intelligence.urlhaus import lookup_urlhaus
from src.prediction.predictor import (
    load_artifacts,
    predict_url,
    validate_url,
)


app = FastAPI(
    title="URLSentry API",
    description=(
        "Machine learning-based phishing URL detection "
        "with optional external threat intelligence."
    ),
    version="2.1.0",
)


class URLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="HTTP or HTTPS URL to analyze.",
        examples=["https://example.com"],
    )


class URLIntelRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL to submit for optional URLhaus lookup.",
    )

    share_with_provider: bool = Field(
        default=False,
        description=(
            "Explicitly authorize sending this URL "
            "to the URLhaus third-party API."
        ),
    )


@app.get("/")
def root():
    return {
        "application": "URLSentry",
        "description": "Phishing URL Detection API",
        "version": "2.1.0",
        "status": "running",
        "documentation": "/docs",
    }


@app.get("/health")
def health():
    try:
        _, config = load_artifacts()

        return {
            "status": "healthy",
            "model": config["model_name"],
            "features": len(config["features"]),
            "database": "enabled",
        }

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Model or application artifacts are unavailable.",
        ) from error


@app.post("/predict")
def predict(request: URLRequest):
    try:
        result = predict_url(request.url)
        saved_result = save_analysis(result)

        return {
            **result,
            "analysis_id": saved_result["id"],
            "analyzed_at": saved_result["analyzed_at"],
            "previously_analyzed": saved_result["previously_analyzed"],
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail="Prediction model is not available.",
        ) from error


@app.get("/history")
def analysis_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    prediction: Literal["phishing", "legitimate"] | None = None,
    risk_level: Literal["low", "elevated", "high"] | None = None,
):
    records = get_history(
        limit=limit,
        offset=offset,
        prediction=prediction,
        risk_level=risk_level,
    )

    return {
        "count": len(records),
        "limit": limit,
        "offset": offset,
        "results": records,
    }


@app.get("/history/{analysis_id}")
def analysis_detail(analysis_id: int):
    if analysis_id < 1:
        raise HTTPException(
            status_code=400,
            detail="Analysis ID must be positive.",
        )

    result = get_analysis(analysis_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return result


@app.get("/stats")
def statistics():
    return get_statistics()


@app.post("/intelligence/lookup")
def intelligence_lookup(request: URLIntelRequest):
    if not request.share_with_provider:
        raise HTTPException(
            status_code=400,
            detail=(
                "Explicit permission is required "
                "before sending the URL to URLhaus."
            ),
        )

    try:
        validated_url = validate_url(request.url)

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    return lookup_urlhaus(validated_url)

