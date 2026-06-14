import pickle

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title="MailShield Pro",
    page_icon="🛡️",
    layout="wide",
)

# =========================
# LOAD MODEL
# =========================

with open("mailshield_model.pkl", "rb") as model_file:
    model = pickle.load(model_file)

with open("vectorizer.pkl", "rb") as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)

if "history" not in st.session_state:
    st.session_state.history = []

# =========================
# CUSTOM CSS
# =========================

st.markdown(
    """
    <style>
    .stApp { background: #f5f7fb; }
    .metric-card {
        background: white;
        padding: 20px;
        border-radius: 15px;
        text-align: center;
        border: 1px solid #e5e7eb;
        box-shadow: 0px 4px 12px rgba(0, 0, 0, 0.06);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# =========================
# HEADER
# =========================

st.markdown(
    """
    <div style="padding: 0 0 12px 0;">
        <h1 style="margin-bottom: 0;">🛡️ MailShield Pro</h1>
        <p style="color: #4b5563; margin-top: 4px;">Security Operations Center for Email & SMS Threat Intelligence</p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.success("🟢 Security Engine Online | Multinomial Naive Bayes Model Loaded Successfully")
st.write("")

# =========================
# INPUT
# =========================
st.markdown("### 📁 Upload Email or Text File")

uploaded_file = st.file_uploader(
    "Upload a .txt file",
    type=["txt"]
)

if uploaded_file is not None:
    message = uploaded_file.read().decode("utf-8")
else:
    message = ""
message = st.text_area(
    "Message Analysis",
    value=message,
    height=180,
    placeholder="Paste email, SMS, WhatsApp message or suspicious text..."
)

history_df = pd.DataFrame(st.session_state.history)
if not history_df.empty:
    st.dataframe(history_df, use_container_width=True, hide_index=True)


# =========================
# RISK FUNCTION
# =========================


def calculate_risk(msg: str):
    msg = msg.lower()
    risk = 0
    indicators = []

    threat_weights = {
        "lottery": 25,
        "winner": 20,
        "won": 15,
        "claim": 20,
        "reward": 15,
        "prize": 20,
        "cash": 15,
        "free": 10,
        "click": 15,
        "urgent": 15,
        "verify": 20,
        "account": 15,
        "bank": 20,
        "offer": 10,
        "congratulations": 15,
    }

    for word, score in threat_weights.items():
        if word in msg:
            risk += score
            indicators.append(word)

    return min(risk, 100), list(dict.fromkeys(indicators))


# =========================
# ANALYZE
# =========================

if st.button("🔍 Analyze Message"):
    if not message.strip():
        st.warning("Please enter a message to analyze.")
    else:
        vector = vectorizer.transform([message])
        prediction = model.predict(vector)
        confidence = round(model.predict_proba(vector).max() * 100, 2)
        risk, indicators = calculate_risk(message)
        category = "SPAM" if prediction[0] == 1 else "SAFE"

        st.session_state.history.append(
            {
                "Category": category,
                "Risk Score": risk,
                "Confidence": confidence,
            }
        )

        st.markdown("### Threat Classification")
        if prediction[0] == 1:
            st.error(
                f"""
🚨 HIGH THREAT MESSAGE DETECTED
Threat Category: SPAM
Model Confidence: {confidence:.2f}%
Immediate Action Recommended
"""
            )
        else:
            st.success(
                f"""
✅ MESSAGE APPEARS SAFE
Threat Level: LOW
Confidence: {confidence:.2f}%
"""
            )

        # KPI cards
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(
                f"""
                <div class="metric-card">
                    <h4>Threat Score</h4>
                    <h1>{risk}/100</h1>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                f"""
                <div class="metric-card">
                    <h4>Category</h4>
                    <h1>{category}</h1>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col3:
            st.markdown(
                f"""
                <div class="metric-card">
                    <h4>Indicators</h4>
                    <h1>{len(indicators)}</h1>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col4:
            st.markdown(
                f"""
                <div class="metric-card">
                    <h4>Confidence</h4>
                    <h1>{confidence:.2f}%</h1>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("## Threat Intelligence Dashboard")
        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=risk,
                title={"text": "Threat Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "red"},
                    "steps": [
                        {"range": [0, 30], "color": "lightgreen"},
                        {"range": [30, 70], "color": "orange"},
                        {"range": [70, 100], "color": "red"},
                    ],
                },
            )
        )
        st.plotly_chart(gauge, use_container_width=True)

        st.subheader("🛡 Threat Assessment")
        if risk >= 70:
            st.error("🔴 HIGH RISK MESSAGE")
        elif risk >= 40:
            st.warning("🟠 MEDIUM RISK MESSAGE")
        else:
            st.success("🟢 LOW RISK MESSAGE")

        st.progress(risk / 100)

        st.markdown("### Threat Indicators")
        if indicators:
            for item in indicators:
                st.write(f"✔ {item}")
        else:
            st.success("No suspicious indicators found")

        st.markdown("## Threat Classification Result")
        if prediction[0] == 1:
            st.error(
                """
🚨 SPAM DETECTED
Threat Level: HIGH
Model Confidence: {confidence}%
Recommendation: Do not click links or share personal information.
""".format(confidence=confidence)
            )
        else:
            st.success(
                """
✅ SAFE MESSAGE
Threat Level: LOW
Model Confidence: {confidence}%
Recommendation: Message appears legitimate.
""".format(confidence=confidence)
            )

        if indicators:
            chart_data = pd.DataFrame({"Indicator": indicators, "Count": [1] * len(indicators)})
            fig = px.pie(chart_data, names="Indicator", values="Count", title="Threat Breakdown")
            st.plotly_chart(fig, use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Keywords Detected", len(indicators))
        with col2:
            st.metric("Threat Score", f"{risk}/100")

        if indicators:
            st.warning("Detected Suspicious Terms: " + ", ".join(indicators))

        st.markdown("## 📈 Threat Intelligence Analytics")
        chart_df = pd.DataFrame({"Metric": ["Threat Score", "Confidence"], "Value": [risk, confidence]})
        st.bar_chart(chart_df.set_index("Metric"))

        st.markdown("## Security Recommendation")
        if risk >= 70:
            st.error("🚨 High Risk: Delete this message immediately and do not interact with links.")
        elif risk >= 30:
            st.warning("⚠ Medium Risk: Verify sender identity before taking action.")
        else:
            st.success("✅ Low Risk: Message appears legitimate.")

        st.subheader("📋 Executive Summary")
        if prediction[0] == 1:
            st.error(
                """
Threat Level: HIGH
The model detected multiple indicators associated with spam, phishing or fraudulent communication.
Confidence: {confidence:.2f}%
Recommended Action: Avoid interacting with this message and verify sender identity.
""".format(confidence=confidence)
            )
        else:
            st.success(
                """
Threat Level: LOW
No major threat indicators detected.
Confidence: {confidence:.2f}%
Recommended Action: Safe to review normally.
""".format(confidence=confidence)
            )

# =========================
# FOOTER
# =========================

st.markdown("---")
st.markdown(
    """
    <div style="background:white; padding:25px; border-radius:15px; box-shadow:0px 4px 12px rgba(0,0,0,0.08);">
        <h2>🛡 Security Operations Center</h2>
        <b>MailShield Pro v2.5</b>
        <br><br>
        Powered by Multinomial Naive Bayes & Threat Intelligence Engine
        <br><br>
        📧 Email Security Monitoring
        📱 SMS Threat Detection
        📊 Risk Intelligence Dashboard
        ⚡ Real-Time Threat Analysis
    </div>
    """,
    unsafe_allow_html=True,
)

