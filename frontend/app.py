import os

import requests
import streamlit as st


API_URL = os.environ.get(
    "URLSENTRY_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")
REQUEST_TIMEOUT = 10
SAMPLE_URLS = {
    "Benign example domain": "https://example.com",
    "Login-style URL (reserved example domain)": (
        "https://paypal-login.example.org/account/verify?session=12345"
    ),
    "IP-hosted URL (documentation address)": (
        "http://192.0.2.10/login/verify?account=demo"
    ),
}


def api_request(method, path, **kwargs):
    try:
        response = requests.request(
            method,
            f"{API_URL}{path}",
            timeout=REQUEST_TIMEOUT,
            **kwargs,
        )
    except requests.RequestException as error:
        st.error(f"Could not connect to the URLSentry API at {API_URL}: {error}")
        return None

    if not response.ok:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        st.error(f"API request failed ({response.status_code}): {detail}")
        return None

    try:
        return response.json()
    except ValueError:
        st.error("The API returned an invalid response.")
        return None


def render_status():
    api_info = api_request("GET", "/")
    if api_info is None:
        return

    try:
        health = requests.get(
            f"{API_URL}/health",
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as error:
        st.warning(f"API is running, but model health could not be checked: {error}")
        return

    if health.ok:
        model = health.json().get("model", "available")
        st.success(f"Backend connected · Model: {model}")
    else:
        st.warning(
            "Backend is running, but the prediction model is unavailable. "
            "Train the model before analyzing URLs."
        )


def render_overview():
    stats = api_request("GET", "/stats")
    if stats is None:
        return

    first, second, third, fourth = st.columns(4)
    first.metric("URLs analyzed", stats["total_analyses"])
    second.metric("Phishing", stats["phishing_count"])
    third.metric("Legitimate", stats["legitimate_count"])
    fourth.metric(
        "Average phishing score",
        f'{stats["average_phishing_score"]:.1%}',
    )

    activity = stats.get("daily_activity", [])
    if activity:
        st.subheader("Recent activity")
        st.bar_chart(
            {
                row["analysis_date"]: row["count"]
                for row in activity
            }
        )


def render_analyzer():
    st.selectbox(
        "Try a sample URL",
        ["(Choose a sample)", *SAMPLE_URLS],
        key="sample_choice",
        on_change=apply_sample,
    )
    st.caption(
        "These examples use reserved domains and IP addresses. URLSentry "
        "analyzes URL text only and does not visit the submitted address."
    )

    with st.form("url-analysis"):
        url = st.text_input(
            "URL to analyze",
            placeholder="https://example.com",
            max_chars=2048,
            key="url_input",
        )
        submit = st.form_submit_button("Analyze URL", type="primary")

    if submit:
        if not url.strip():
            st.warning("Enter a URL to analyze.")
        else:
            result = api_request("POST", "/predict", json={"url": url.strip()})
            if result is not None:
                if (
                    result["url"]
                    != st.session_state.get("last_analysis_url")
                ):
                    st.session_state["urlhaus-consent"] = False
                st.session_state["last_analysis_url"] = result["url"]

                with st.container(border=True):
                    st.subheader("Analysis result")
                    prediction, risk, score = st.columns(3)
                    prediction.metric(
                        "Prediction",
                        result["prediction"].title(),
                    )
                    risk.metric("Risk level", result["risk_level"].title())
                    score.metric(
                        "Phishing score",
                        f'{result["score_percentage"]:.2f}%',
                    )
                    st.progress(
                        result["phishing_score"],
                        text=(
                            f'Model threshold: '
                            f'{result["decision_threshold"]:.2%}'
                        ),
                    )
                    if result["previously_analyzed"]:
                        st.info(
                            "This exact URL was analyzed before by the "
                            "URLSentry ML model."
                        )
                    else:
                        st.caption(
                            "First recorded analysis of this exact URL by "
                            "the URLSentry ML model."
                        )
                    st.caption(
                        f'Model: {result["model_name"]} · '
                        f'Analysis #{result["analysis_id"]}'
                    )

                with st.expander("Features used for this prediction", expanded=True):
                    feature_rows = [
                        {"Feature": name, "Value": value}
                        for name, value in result["features"].items()
                    ]
                    st.dataframe(
                        feature_rows,
                        width="stretch",
                        hide_index=True,
                    )

    previous_url = st.session_state.get("last_analysis_url")
    if previous_url:
        st.divider()
        st.subheader("Optional URLhaus lookup")
        st.caption(
            "This sends the URL to a third party. A URLhaus non-match does "
            "not mean the URL is safe."
        )
        consent = st.checkbox(
            "I consent to sharing this URL with URLhaus",
            key="urlhaus-consent",
        )
        if st.button("Check URLhaus", disabled=not consent):
            result = api_request(
                "POST",
                "/intelligence/lookup",
                json={
                    "url": previous_url,
                    "share_with_provider": True,
                },
            )
            if result is not None:
                if result.get("status") == "unavailable":
                    st.warning(
                        "URLhaus could not check this URL; no URLhaus "
                        "detection result is available."
                    )
                elif result.get("cache_hit"):
                    st.caption(
                        "Previously checked by URLhaus; displaying the "
                        "cached result."
                    )
                else:
                    st.caption(
                        "Checked by URLhaus just now; no earlier cached "
                        "result was available."
                    )

                if result.get("matched"):
                    st.error("URLhaus reports a malware-distribution match.")
                    if result.get("threat"):
                        st.write(f'Threat type: {result["threat"]}')
                elif result.get("status") == "not_found":
                    st.info(
                        "URLhaus found no matching record. This does not "
                        "mean the URL is safe."
                    )
                else:
                    st.info(result.get("message", "No URLhaus match reported."))


def apply_sample():
    selected = st.session_state["sample_choice"]
    st.session_state["url_input"] = SAMPLE_URLS.get(selected, "")


def render_history():
    prediction = st.selectbox(
        "Prediction filter",
        ["All", "Phishing", "Legitimate"],
    )
    params = {"limit": 50}
    if prediction != "All":
        params["prediction"] = prediction.lower()

    result = api_request("GET", "/history", params=params)
    if result is not None:
        records = result["results"]
        if records:
            st.dataframe(records, width="stretch", hide_index=True)
        else:
            st.info("No analyses found.")


st.set_page_config(
    page_title="URLSentry",
    page_icon="U",
    layout="wide",
)

st.markdown(
    """
    <style>
    .main .block-container {
        max-width: 1180px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }
    .urlsentry-hero {
        padding: 1.7rem 2rem;
        margin-bottom: 1.2rem;
        border: 1px solid rgba(148, 163, 184, 0.28);
        border-radius: 18px;
        background: linear-gradient(120deg, #0f172a, #1e3a8a);
        color: #f8fafc;
    }
    .urlsentry-hero .eyebrow {
        margin: 0 0 0.4rem;
        color: #bfdbfe;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
    }
    .urlsentry-hero h1 {
        margin: 0;
        color: #f8fafc;
        font-size: 2.4rem;
    }
    .urlsentry-hero .subtitle {
        margin: 0.35rem 0 0;
        color: #dbeafe;
    }
    [data-testid="stMetric"] {
        padding: 0.85rem 1rem;
        border: 1px solid rgba(148, 163, 184, 0.24);
        border-radius: 12px;
        background: rgba(148, 163, 184, 0.08);
    }
    div[data-baseweb="tab-list"] {
        gap: 0.4rem;
    }
    </style>
    <section class="urlsentry-hero">
        <p class="eyebrow">URL threat analysis</p>
        <h1>URLSentry</h1>
        <p class="subtitle">
            Inspect suspicious links using URL structure and threat intelligence.
        </p>
    </section>
    """,
    unsafe_allow_html=True,
)
st.session_state.setdefault("url_input", "")
render_status()

overview, analyzer, history = st.tabs(
    ["Overview", "Analyze URL", "History"]
)
with overview:
    render_overview()
with analyzer:
    render_analyzer()
with history:
    render_history()
