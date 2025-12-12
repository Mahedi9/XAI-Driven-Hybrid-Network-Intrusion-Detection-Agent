# app.py
import streamlit as st
import pickle, os, json
import pandas as pd
import numpy as np
import shap
import matplotlib.pyplot as plt
import streamlit.components.v1 as components
from shap.plots import force
import matplotlib.pyplot as plt

st.set_page_config(page_title="NIDS", page_icon="🛡️", layout="wide")

# -----------------------------------
# Load artifacts 
# -----------------------------------
MODEL_DIR = "models"

@st.cache_resource
def load_artifacts():
    scaler = pickle.load(open(os.path.join(MODEL_DIR, "scaler.pkl"), "rb"))
    model = pickle.load(open(os.path.join(MODEL_DIR, "xgb_model.pkl"), "rb"))
    features = pickle.load(open(os.path.join(MODEL_DIR, "features.pkl"), "rb"))
    label_encoder = pickle.load(open(os.path.join(MODEL_DIR, "label_encoder.pkl"), "rb"))
    return scaler, model, features, label_encoder

scaler, model_xgb, selected_features, label_encoder = load_artifacts()

# -----------------------------------
# Expert Rules
# -----------------------------------
def expert_rules(row):
    rules = []

    # 1) logged_in: not logged in + many connections -> suspicious
    # Rationale: many normal sessions are logged in; many unauthenticated
    # high-count sessions can indicate probing or attacks.
    if (row.get('logged_in', 0) == 0) and (row.get('count', 0) >= 100):
        rules.append("Not logged in with high connection count (possible probe/exploit)")

    # 2) count: extremely high connection count -> DoS/scan
    # We use a high threshold (>=200) since 75% quantile is 144, 90% ~256.
    if row.get('count', 0) >= 200:
        rules.append("High connection count (>200) — possible DoS/scan")

    # 3) serror_rate: very high SYN error rate -> SYN flood / many failed SYNs
    # serror_rate is often 0 or 1; require near-1 to reduce false positives.
    if row.get('serror_rate', 0.0) >= 0.9:
        rules.append("Very high serror_rate (possible SYN flood)")

    # 4) srv_serror_rate: high service-level SYN errors -> service-targeted flood
    if row.get('srv_serror_rate', 0.0) >= 0.9:
        rules.append("Very high srv_serror_rate (service-level SYN errors)")

    # 5) same_srv_rate: very low same_srv_rate => traffic to many different services (scan)
    # Based on distribution, low values (<=0.1) are unusual and indicate scanning/randomness.
    if row.get('same_srv_rate', 1.0) <= 0.10:
        rules.append("Low same_srv_rate (diverse services — possible scan)")

    # 6) dst_host_srv_count: destination host seen serving many connections (victim of scanning/DoS)
    # Use >=200 (near top-tail)
    if row.get('dst_host_srv_count', 0) >= 200:
        rules.append("High dst_host_srv_count (dest host receiving many service connections)")

    # 7) dst_host_same_srv_rate: destination host same-service rate == 1 -> focused host scan/port probing
    if row.get('dst_host_same_srv_rate', 0.0) == 1.0:
        rules.append("dst_host_same_srv_rate == 1.0 (targeted service access on host — possible scan)")

    # 8) dst_host_serror_rate: high dest-host SYN error rate -> target being flooded or probed
    if row.get('dst_host_serror_rate', 0.0) >= 0.9:
        rules.append("High dst_host_serror_rate (dest-host SYN errors)")

    # 9) dst_host_srv_serror_rate: high dest-host service SYN error rate -> service-level victim
    if row.get('dst_host_srv_serror_rate', 0.0) >= 0.9:
        rules.append("High dst_host_srv_serror_rate (dest-host service SYN errors)")

    # 10) service_http: HTTP access without login (suspicious for web exploits / data exfiltration)
    # Only flag if not logged in (reduce FP)
    if (row.get('service_http', 0) == 1) and (row.get('logged_in', 1) == 0) and (row.get('serror_rate', 0) >= 0.6 or row.get('same_srv_rate', 1) <= 0.15 ):
         rules.append("HTTP access without login + abnormal traffic → possible exploitation")

    # 11) service_private: private service used (often unusual) -> flag for inspection
    if row.get('service_private', 0) == 1:
        rules.append("Access to PRIVATE service (monitor for suspicious internal traffic)")

    # 12) flag_S0: S0 indicates many half-open (no reply) connections — suspicious
    if row.get('flag_S0', 0) == 1:
        rules.append("Flag S0 present (half-open connections — suspicious)")

    # 13) flag_SF: SF is common for many normal closes, but in combination with high errors it's suspicious.
    # We use flag_SF only when combined with high serror or high dst_host_serror to reduce false alarms.
    if (row.get('flag_SF', 0) == 1) and ((row.get('serror_rate', 0.0) >= 0.8) or (row.get('dst_host_serror_rate', 0.0) >= 0.8)):
        rules.append("Flag SF + high SYN errors (suspicious sequence)")

    return rules


# -----------------------------------
# Agent 
# -----------------------------------
class IntrusionAgent:
    def __init__(self, scaler, model, selected_features, label_encoder):
        self.scaler = scaler
        self.model = model
        self.selected_features = selected_features
        self.le = label_encoder

    def perceive(self, row):
        df = pd.DataFrame([row])
        df13 = df[self.selected_features]
        scaled = self.scaler.transform(df13)
        return scaled

    def ml_decision(self, processed):
        pred = int(self.model.predict(processed)[0])  # 0=anomaly, 1=normal
        label = self.le.inverse_transform([pred])[0]

        # probability of ANOMALY = class 0
        conf_anomaly = float(self.model.predict_proba(processed)[0][0])

        return pred, label, conf_anomaly

    def rule_decision(self, row):
        return expert_rules(row)

    def decide_and_act(self, row):
        processed = self.perceive(row)
        ml_pred, ml_label, ml_conf_anomaly = self.ml_decision(processed)
        rules = self.rule_decision(row)

        rule_fired = len(rules) > 0
        ml_anomaly = (ml_pred == 0)

        # ======================================================
        # PRIORITY 1 — RULES + ML → BLOCK
        # ======================================================
        if ml_anomaly and rule_fired:
            return {
                "is_anomaly": True,
                "ml_pred": ml_pred,
                "ml_label": ml_label,
                "ml_confidence": ml_conf_anomaly,
                "rules_triggered": rules,
                "action": "BLOCK",
                "reason": ["Both ML and Rules indicate anomaly"]
            }

        # ======================================================
        # PRIORITY 2 — RULES ONLY → BLOCK
        # ======================================================
        if rule_fired:
            return {
                "is_anomaly": True,
                "ml_pred": ml_pred,
                "ml_label": ml_label,
                "ml_confidence": ml_conf_anomaly,
                "rules_triggered": rules,
                "action": "BLOCK",
                "reason": rules
            }

        # ======================================================
        # PRIORITY 3 — ML ANOMALY
        # ======================================================
        if ml_anomaly:
            if ml_conf_anomaly >= 0.75:
                act = "BLOCK"
            else:
                act = "ALERT"
            return {
                "is_anomaly": True,
                "ml_pred": ml_pred,
                "ml_label": ml_label,
                "ml_confidence": ml_conf_anomaly,
                "rules_triggered": [],
                "action": act,
                "reason": [f"ML anomaly probability = {ml_conf_anomaly:.3f}"]
            }

        # ======================================================
        # PRIORITY 4 — ML says normal but anomaly probability medium
        # ALERT THRESHOLD FIXED HERE ↓↓↓
        # ======================================================
        if 0.20 <= ml_conf_anomaly < 0.75:   # <-- FIXED HERE
            return {
                "is_anomaly": False,
                "ml_pred": ml_pred,
                "ml_label": ml_label,
                "ml_confidence": ml_conf_anomaly,
                "rules_triggered": [],
                "action": "ALERT",
                "reason": [f"Moderate anomaly likelihood = {ml_conf_anomaly:.3f}"]
            }

        # ======================================================
        # PRIORITY 5 — SAFE NORMAL
        # ======================================================
        return {
            "is_anomaly": False,
            "ml_pred": ml_pred,
            "ml_label": ml_label,
            "ml_confidence": ml_conf_anomaly,
            "rules_triggered": [],
            "action": "ALLOW",
            "reason": []
        }





agent = IntrusionAgent(scaler, model_xgb, selected_features, label_encoder)

# -----------------------------------
# UI Layout
# -----------------------------------
st.title("XAI-Driven Hybrid Network Intrusion Detection Agent")
st.caption("ML anomaly detection + rule-based detection + SHAP explainability")

left, right = st.columns([1, 2])

# -----------------------------------
# Inputs
# -----------------------------------
with left:
    st.header("Input (13 features)")

    input_mode = st.radio("Select input method:", ["Manual", "Paste JSON"])

    user_input = {}

    if input_mode == "Manual":
        st.subheader("Manual Input (13 features)")
        
        cols = st.columns(1)
        for feat in selected_features:
            user_input[feat] = st.number_input(feat, value=0.0, format="%.3f", key=f"man_{feat}")
    else:
        st.subheader("JSON Input (paste full JSON for the 13 features)")
        default_json = json.dumps({
            "logged_in": 0.00,
            "count": 0.00,
            "serror_rate": 0.00,
            "srv_serror_rate": 0.00,
            "same_srv_rate": 0.00,
            "dst_host_srv_count": 0.00,
            "dst_host_same_srv_rate": 0.00,
            "dst_host_serror_rate": 0.00,
            "dst_host_srv_serror_rate": 0.00,
            "service_http": 0.00,
            "service_private": 0.00,
            "flag_S0": 0.00,
            "flag_SF": 0.00
        }, indent=2)
        json_text = st.text_area("Paste JSON here", value=default_json, height=280)
        if st.button("Load JSON"):
            try:
                parsed = json.loads(json_text)
            except Exception as e:
                st.error(f"Invalid JSON: {e}")
                parsed = None

            if parsed is not None:
                missing = [f for f in selected_features if f not in parsed]
                if missing:
                    st.error(f"JSON is missing features: {missing}")
                else:
                    user_input = {f: parsed[f] for f in selected_features}
                    st.success("JSON loaded ✅ — ready to analyze")
                    # store last input for explainability
                    st.session_state["last_input_json"] = user_input


    # Analyze button (works for both manual and JSON)
    if st.button("Analyze sample"):
        # determine the actual input dict
        if input_mode == "Manual":

            pass
        else:
            
            if not user_input:
                try:
                    parsed = json.loads(json_text)
                    missing = [f for f in selected_features if f not in parsed]
                    if missing:
                        st.error(f"JSON is missing features: {missing}")
                        st.stop()
                    user_input = {f: float(parsed[f]) for f in selected_features}

                except Exception as e:
                    st.error(f"Invalid JSON: {e}")
                    st.stop()

        # final check
        missing = [f for f in selected_features if f not in user_input]
        if missing:
            st.error(f"Input is missing features: {missing}")
        else:
            df_input = pd.DataFrame([user_input])
            decision = agent.decide_and_act(user_input)

            st.subheader("Result")
            if decision["action"] == "BLOCK":
                st.error("Action: BLOCK")
            elif decision["action"] == "ALERT":
                st.warning("Action: ALERT")
            else:
                st.success("Action: ALLOW")
            
            st.write("Is Anomaly:", decision["is_anomaly"])
            st.write("ML Label:", decision["ml_label"])
            st.write("ML Prediction:", decision["ml_pred"])
            st.write("ML Anomaly Probability:", f"{decision['ml_confidence']:.4f}")

            st.write("Triggered Rules:", decision["rules_triggered"])
            st.write("Reason:", decision["reason"])

            # put into session for explainability side
            st.session_state["last_input"] = df_input
            st.session_state["last_decision"] = decision


# -----------------------------------
# Explainability
# -----------------------------------
with right:
    st.header("Explainability & SHAP")

    if "last_input" not in st.session_state:
        st.info("Submit a sample on the left for SHAP explanations.")
    else:
        df_input = st.session_state["last_input"]

        # Scale input
        scaled = scaler.transform(df_input[selected_features])

        # SHAP explainer (cached)
        @st.cache_resource
        def build_explainer(_model):
            return shap.TreeExplainer(_model)

        explainer = build_explainer(model_xgb)

        # SHAP values using the modern API
        shap_raw = explainer(scaled)
        shap_values = shap_raw.values        # shape (1, 13)
        expected_value = shap_raw.base_values[0]

        # FIX: anomaly probability = column 0
        prob = model_xgb.predict_proba(scaled)[0][0]
        st.metric("Intrusion Probability", f"{prob:.4f}")

        # Local SHAP table
        st.subheader("Local SHAP Values (13 Features)")
        shap_df = pd.DataFrame({
            "Feature": selected_features,
            "SHAP value": shap_values[0]
        })
        shap_df = shap_df.reindex(shap_df["SHAP value"].abs().sort_values(ascending=False).index)
        st.dataframe(shap_df)

    

        # Global summary
        st.subheader("Global SHAP Summary")

        @st.cache_data
        def load_training_data():
            df = pd.read_csv("NID_data.csv")

            # One-hot encode as during training
            df = pd.get_dummies(df, columns=["service", "flag"])

            # Ensure expected dummy columns exist
            expected_dummies = ["service_http", "service_private", "flag_S0", "flag_SF"]
            for col in expected_dummies:
                if col not in df.columns:
                    df[col] = 0

            # Keep the final 13 model features
            X_train = df[selected_features]

            # Scale with loaded scaler
            X_train_scaled = scaler.transform(X_train)
            return X_train_scaled

        X_train_scaled = load_training_data()
        shap_global = explainer(X_train_scaled)

        shap_values_global = shap_global.values
        data_for_plot = pd.DataFrame(X_train_scaled, columns=selected_features)

        fig = plt.figure(figsize=(8, 5))
        shap.summary_plot(
            shap_values_global,
            data_for_plot,              
            feature_names=selected_features,
            show=False
        )
        st.pyplot(fig)

st.markdown("---")
st.caption("Explainability computed on the 13 original features.")
