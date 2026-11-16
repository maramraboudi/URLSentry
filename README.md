# URLSentry
### Machine Learning-Based Phishing URL Detection System

URLSentry is a cybersecurity project that uses machine learning to identify potentially phishing URLs through URL-based feature extraction and classification.

The platform combines a trained machine learning model, a REST API, persistent analysis history, and optional external threat intelligence through URLhaus.

The objective is to provide a structured and explainable workflow for analyzing suspicious URLs without directly visiting the submitted websites.

## Key Features

### Machine Learning Detection
- URL-based feature extraction.
- Machine learning classification of phishing and legitimate URLs.
- Phishing score and configurable decision threshold.
- Risk classification: Low, Elevated, and High.
- Model evaluation and feature importance analysis.

### URL Analysis API
- FastAPI REST API.
- URL validation.
- Prediction endpoint.
- Analysis history and individual analysis retrieval.
- Statistical summaries.

### Threat Intelligence Integration
- Optional URLhaus API integration.
- Explicit user consent before submitting URLs to the external provider.
- SQLite-backed intelligence caching.
- Separate malware-distribution intelligence results from ML phishing predictions.
- Graceful handling of API errors and unavailable services.

**Important:** URLhaus primarily provides malware-distribution URL intelligence. A URL not found in URLhaus is not necessarily safe or legitimate.

### Data Persistence
- SQLite database.
- Saved prediction records.
- Analysis history and filtering.
- Threat intelligence cache with expiration.

### Testing
- Automated tests using pytest.
- API endpoint tests.
- Database tests.
- URL feature extraction tests.
- URLhaus integration tests using mocked responses.

## Architecture

```text
                    URLSentry
                        |
          +-------------+-------------+
          |                           |
     FastAPI API                 ML Pipeline
          |                           |
    +-----+------+              Feature Extraction
    |     |      |                     |
 Predict History Statistics       Trained Model
    |     |      |
    +-----+------+
          |
      SQLite DB
          |
    +-----+----------------+
    |                      |
Analysis History      URLhaus Cache
                           |
                    URLhaus API
                    (Optional)
```

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas, NumPy |
| API Framework | FastAPI |
| API Server | Uvicorn |
| Database | SQLite |
| Threat Intelligence | URLhaus API |
| Testing | Pytest |
| Data Visualization | Matplotlib, Seaborn |
| Environment | Ubuntu on WSL |

## Project Structure

```text
URLSentry/
├── app/
│   └── main.py
├── src/
│   ├── data/
│   ├── evaluation/
│   ├── features/
│   ├── intelligence/
│   ├── prediction/
│   └── training/
├── tests/
├── data/
├── models/
├── reports/
│   ├── eda/
│   ├── figures/
│   ├── final_test_metrics.csv
│   ├── feature_importance.csv
│   └── model_comparison.csv
├── frontend/
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/maramraboudi/URLSentry.git
cd URLSentry
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file:

```bash
touch .env
```

For optional URLhaus integration, configure your API key:

```env
URLHAUS_AUTH_KEY=your_urlhaus_api_key
```

Keep your API key private. Never commit `.env` or expose credentials in screenshots or logs.

URLhaus integration is optional. The machine learning prediction functionality is independent of this external service.

### 5. Start the API

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## API Documentation

Once the API is running, interactive documentation is available at:

http://127.0.0.1:8000/docs

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | API information |
| GET | `/health` | Application health |
| POST | `/predict` | Analyze a URL |
| GET | `/history` | Retrieve analysis history |
| GET | `/history/{analysis_id}` | Retrieve a specific analysis |
| GET | `/stats` | Retrieve analysis statistics |
| POST | `/intelligence/lookup` | Optional URLhaus lookup |

### Example prediction request

```bash
curl -X POST http://127.0.0.1:8000/predict \
-H "Content-Type: application/json" \
-d '{"url":"https://example.com"}'
```

### Example URLhaus lookup

External submission requires explicit consent:

```bash
curl -X POST http://127.0.0.1:8000/intelligence/lookup \
-H "Content-Type: application/json" \
-d '{"url":"https://example.com","share_with_provider":true}'
```

## Running Tests

Run the automated test suite:

```bash
pytest -v
```

The current verified test suite contains 36 passing tests.

## Reports and Evaluation

The `reports/` directory contains generated project evaluation artifacts, including:

- Model comparison results.
- Final test metrics.
- Classification report.
- Feature importance.
- ROC and precision-recall curves.
- Confusion matrix.
- Dataset exploration results.
- Misclassified URL records.

These artifacts support the analysis and evaluation of the trained classification models.

## Security Considerations

- URL analysis uses extracted URL characteristics rather than visiting the submitted website.
- External URLhaus lookups require explicit user consent.
- API credentials must be stored in environment variables.
- URLhaus results are separate from machine learning classification.
- A missing threat-intelligence match does not guarantee that a URL is safe.
- Model scores should not automatically be interpreted as calibrated probabilities.

## Development Status

The machine learning pipeline, FastAPI backend, SQLite persistence, URLhaus integration, and automated tests have been implemented.

The Streamlit frontend is planned as the next development stage.

## Future Improvements

- Interactive Streamlit cybersecurity dashboard.
- Advanced analysis visualization.
- Exportable analysis reports.
- Enhanced threat intelligence correlation.
- Additional model evaluation and explainability.
- Deployment and containerization.

## Author

**Maram Raboudi**

Cybersecurity Engineering Student

GitHub: [@maramraboudi](https://github.com/maramraboudi)

---

*URLSentry is an educational cybersecurity project developed to explore machine learning, phishing detection, API development, and threat intelligence integration.*
