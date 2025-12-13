# 🛡️ XAI-Driven-Hybrid-Network-Intrusion-Detection-Agent
ML-Powered • Rule-Based • Explainable • Real-Time Decision System

This project implements a hybrid Network Intrusion Detection System (NIDS) that combines:

Machine Learning (XGBoost)

Expert rule-based inference

Explainable AI (SHAP)

Interactive real-time analysis (Streamlit)

The system classifies network traffic into:

ALLOW, ALERT, or BLOCK

based on both model probability and handcrafted security rules.

📌 Features

🔷 Hybrid Decision Engine

ML classifier detects anomalies (class 0 = anomaly).

Expert rules detect known network abuse patterns.

Smart decision matrix merges ML + Rules.

🔷 Explainability (XAI)

SHAP Force Plot (local explanation).

SHAP Summary Plot (global importance).

Transparent, interpretable security decisions.

🔷 Interactive UI

Manual or JSON input.

Real-time anomaly scoring.

Rule trigger visualization.

Probability-based security actions.

🔷 Professional Model Pipeline

Preprocessed dataset

Feature selection (13 features)

Scaling (StandardScaler)

XGBoost model

Label encoding

Exported artifacts (.pkl)

📁 Project Structure

XAI-Driven-Hybrid-Network-Intrusion-Detection-Agent/

│── app.py                         # Streamlit application (run this)

│── models/

│   ├── scaler.pkl

│   ├── xgb_model.pkl

│   ├── features.pkl

│   ├── label_encoder.pkl

│── NID_data.csv                   # Dataset

│── Intrusion_Agent.ipynb          # Full training notebook (optional)

│── README.md

│── requirements.txt

📝 About the Notebook

Intrusion_Agent.ipynb contains the complete model training pipeline.
It is included only for users who want to explore how the model was trained.

⚠️ It is NOT required to run the Streamlit application.

⚙️ Installation & Setup

1️⃣ Install dependencies:

pip install -r requirements.txt

2️⃣ Run the Streamlit web interface:

streamlit run app.py


That’s it — the UI will launch in your browser.

🧪 Model Features (13 Selected Inputs)

logged_in  
count  
serror_rate  
srv_serror_rate  
same_srv_rate  
dst_host_srv_count  
dst_host_same_srv_rate  
dst_host_serror_rate  
dst_host_srv_serror_rate  
service_http  
service_private  
flag_S0  
flag_SF


These features are loaded from features.pkl to ensure consistency between training and real-time inference.

🧠 Hybrid Decision Logic

🔍 ML-Based Probability Thresholds

(Probability of anomaly = class 0)

| Probability     | Meaning    | Action    |
| --------------- | ---------- | --------- |
| **≥ 0.75**      | High risk  | **BLOCK** |
| **0.20 – 0.75** | Suspicious | **ALERT** |
| **< 0.20**      | Safe       | **ALLOW** |


🔥 Example JSON Input:

{

  "logged_in": 0,
  
  "count": 150,
  
  "serror_rate": 0.20,
  
  "srv_serror_rate": 0.10,
  
  "same_srv_rate": 0.05,
  
  "dst_host_srv_count": 230,
  
  "dst_host_same_srv_rate": 1.0,
  
  "dst_host_serror_rate": 0.10,
  
  "dst_host_srv_serror_rate": 0.30,
  
  "service_http": 1,
  
  "service_private": 0,
  
  "flag_S0": 1,
  
  "flag_SF": 0
  
}

🧠 Explainability (XAI)

This system provides:

Local SHAP Force Plot – explains why THIS traffic sample is classified.

Global SHAP Summary Plot – shows which features drive the model overall.

SHAP tables – numerical importance values for transparency.

Project link: https://xai-driven-hybrid-network-intrusion-detection-agent-kadace5rlg.streamlit.app/
