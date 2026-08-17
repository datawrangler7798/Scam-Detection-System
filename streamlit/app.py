import html
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

import pandas as pd
import streamlit as st

from evaluate import evaluate_model
from pipeline.scam_detection.detector import ScamDetector


st.set_page_config(page_title="Sentinel | Scam Detection", page_icon="🛡️", layout="wide")


def inject_styles():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
    :root { --ink:#eaf5ff; --muted:#91a7bd; --line:rgba(133,190,233,.17); --cyan:#4ee3ff; }
    .stApp { background:#06111f; color:var(--ink); font-family:'Manrope',sans-serif; }
    .stApp::before { content:''; position:fixed; inset:0; pointer-events:none; z-index:0; background:linear-gradient(rgba(78,227,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(78,227,255,.035) 1px,transparent 1px),radial-gradient(circle at 74% 7%,#123f5a 0,transparent 27%),radial-gradient(circle at 15% 82%,#132b55 0,transparent 25%); background-size:46px 46px,46px 46px,100% 100%,100% 100%; }
    .stApp::after { content:''; position:fixed; width:520px; height:520px; right:-160px; top:130px; border-radius:50%; pointer-events:none; z-index:0; background:radial-gradient(circle,rgba(78,227,255,.14) 0,rgba(78,227,255,.03) 32%,transparent 68%); filter:blur(3px); animation:drift 12s ease-in-out infinite; }
    @keyframes drift { 0%,100%{transform:translate(0,0) scale(1)} 50%{transform:translate(-85px,70px) scale(1.16)} }
    @keyframes pulse { 0%,100%{box-shadow:0 0 0 0 rgba(78,227,255,.55)} 50%{box-shadow:0 0 0 8px rgba(78,227,255,0)} }
    .main .block-container { max-width:1240px; padding:2.3rem 3rem 4rem; position:relative; z-index:1; }
    #MainMenu,footer,header { visibility:hidden; }
    .hero { display:flex; align-items:center; justify-content:space-between; padding:1.2rem 0 2.5rem; }
    .brand { display:flex; gap:14px; align-items:center; }.brand-mark { display:grid;place-items:center;width:42px;height:42px;border:1px solid rgba(78,227,255,.58);border-radius:13px;background:linear-gradient(135deg,#123850,#071827);box-shadow:0 0 28px rgba(78,227,255,.15);font-size:22px; }
    .eyebrow { color:var(--cyan);font:500 10px 'DM Mono',monospace;text-transform:uppercase;letter-spacing:.18em;margin-bottom:3px; }.brand-name { font-size:20px;font-weight:800;letter-spacing:-.045em; }
    .system-live { display:flex;align-items:center;gap:8px;border:1px solid var(--line);padding:8px 12px;border-radius:999px;color:#b8cce0;font:10px 'DM Mono',monospace;letter-spacing:.08em; }.live-dot { width:7px;height:7px;background:#62e6a7;border-radius:50%;animation:pulse 2s infinite; }
    .hero-copy { margin-bottom:1.45rem; }.hero-copy h1 { font-size:clamp(2rem,4vw,3.25rem);letter-spacing:-.06em;margin:0 0 .4rem;line-height:1.05; }.hero-copy p { color:var(--muted);font-size:1rem;margin:0;max-width:630px; }
    .feature-row { display:flex;gap:10px;flex-wrap:wrap;margin:1.15rem 0 1.8rem; }.feature { color:#a9c3d9;font:10px 'DM Mono',monospace;border:1px solid var(--line);background:rgba(14,34,55,.58);border-radius:6px;padding:7px 9px; }.feature span { color:var(--cyan);margin-right:6px; }
    .glass { background:linear-gradient(145deg,rgba(17,39,63,.88),rgba(8,21,37,.7));border:1px solid var(--line);border-radius:18px;padding:1.2rem;box-shadow:0 18px 55px rgba(0,0,0,.18); }
    div[data-baseweb="tab-list"] { gap:12px;background:transparent;margin-bottom:1.2rem; } button[data-baseweb="tab"] { background:rgba(14,34,55,.58);color:#9db3c7;border:1px solid var(--line);border-radius:8px;padding:8px 15px;height:auto;font:600 12px 'Manrope',sans-serif; } button[data-baseweb="tab"][aria-selected="true"] { background:rgba(78,227,255,.12);color:#dffaff;border-color:rgba(78,227,255,.42); }
    div[data-testid="stTextArea"] textarea,div[data-testid="stNumberInput"] input { background:#071829!important;color:#eaf5ff!important;border:1px solid rgba(133,190,233,.25)!important;border-radius:10px!important;font-family:'DM Mono',monospace; } div[data-testid="stTextArea"] label,div[data-testid="stFileUploader"] label,div[data-testid="stNumberInput"] label { color:#c8d8e7!important;font-weight:600!important;font-size:.84rem!important; }
    .stButton > button { border:0;border-radius:9px;background:linear-gradient(135deg,#30c8ed,#48e5c1);color:#04121e;font-family:'Manrope',sans-serif;font-weight:800;padding:.65rem 1.05rem;box-shadow:0 8px 25px rgba(78,227,255,.18); }.stButton > button:hover { background:linear-gradient(135deg,#67e9ff,#7df4d4);transform:translateY(-1px); }div[data-testid="stAlert"] { border-radius:10px;border:1px solid var(--line); }
    div[data-testid="stMetric"] { background:rgba(11,30,49,.72);border:1px solid var(--line);border-radius:13px;padding:15px; }div[data-testid="stMetric"] label { color:#92a9bd!important; }div[data-testid="stMetric"] [data-testid="stMetricValue"] { color:#e9f8ff!important; }
    .result-card { border-radius:14px;padding:1.35rem;border:1px solid var(--line);background:rgba(7,22,38,.7); }.result-card.scam { border-color:rgba(255,107,107,.55);background:linear-gradient(135deg,rgba(100,25,37,.45),rgba(18,25,42,.7)); }.result-card.safe { border-color:rgba(98,230,167,.46);background:linear-gradient(135deg,rgba(18,87,69,.32),rgba(18,25,42,.7)); }.result-label { color:#94abc0;font:500 10px 'DM Mono',monospace;letter-spacing:.16em;text-transform:uppercase; }.result-value { margin:.25rem 0;font-size:1.85rem;font-weight:800;letter-spacing:-.05em; }.result-desc { color:#a7bacb;font-size:.86rem; }.risk-title { font-size:.82rem;font-weight:800;letter-spacing:.04em;color:#dbecfa;margin-bottom:.6rem; }.risk-item { color:#b8c9d8;font-size:.85rem;padding:.52rem 0;border-bottom:1px solid rgba(133,190,233,.1); }.risk-item::before { content:'✦';color:#ff9b77;margin-right:8px; }
    @media(max-width:720px){.main .block-container{padding:1.3rem 1rem 3rem}.system-live{display:none}}
    </style>""", unsafe_allow_html=True)


def result_card(result):
    label = str(result.get("label", "Uncertain"))
    is_scam, is_safe = label == "Scam", label == "Not Scam"
    tone = "scam" if is_scam else "safe" if is_safe else ""
    signal = "THREAT DETECTED" if is_scam else "MESSAGE CLEARED" if is_safe else "REVIEW REQUIRED"
    desc = "Do not engage, click links, or share any details." if is_scam else "No high-confidence scam signals were found." if is_safe else "Signals are mixed. Review the message carefully."
    st.markdown(f'<div class="result-card {tone}"><div class="result-label">{signal}</div><div class="result-value">{html.escape(label)}</div><div class="result-desc">{desc}</div></div>', unsafe_allow_html=True)


inject_styles()
detector = ScamDetector()
st.markdown('''<div class="hero"><div class="brand"><div class="brand-mark">🛡</div><div><div class="eyebrow">Personal security layer</div><div class="brand-name">SENTINEL</div></div></div><div class="system-live"><span class="live-dot"></span> PROTECTION ENGINE ONLINE</div></div><div class="hero-copy"><h1>Know the threat before<br>it reaches you.</h1><p>Analyze suspicious messages for the patterns scammers use to create urgency, steal credentials, and take your money.</p></div><div class="feature-row"><div class="feature"><span>◈</span> LINK &amp; URGENCY SIGNALS</div><div class="feature"><span>◈</span> SOCIAL ENGINEERING</div><div class="feature"><span>◈</span> AI-POWERED REVIEW</div></div>''', unsafe_allow_html=True)

tab1, tab2 = st.tabs(["Message scanner", "Dataset evaluation"])
with tab1:
    st.markdown('<div class="glass"><div class="eyebrow">01 / Scan message</div><h3 style="margin:4px 0 16px;">Run a threat check</h3>', unsafe_allow_html=True)
    user_input = st.text_area("Paste a text, email, or direct message", height=150, placeholder="Example: Congratulations! You have won $1,000. Claim it now before your reward expires...")
    scan = st.button("Scan for scam signals  →", type="primary")
    st.markdown('</div>', unsafe_allow_html=True)
    if scan:
        if not user_input.strip(): st.warning("Paste a message before starting a scan.")
        else:
            with st.spinner("Inspecting language patterns and risk signals..."): result = detector.detect(user_input)
            st.markdown('<div style="height:18px"></div>', unsafe_allow_html=True)
            left, right = st.columns([1.35, 1], gap="large")
            with left:
                result_card(result)
                intent = html.escape(str(result.get("intent", "Unknown")))
                st.markdown(f'<div style="height:12px"></div><div class="glass"><div class="result-label">Detected intent</div><div style="font-size:1.05rem;font-weight:700;margin-top:6px;">{intent}</div></div>', unsafe_allow_html=True)
            with right:
                st.markdown('<div class="glass"><div class="risk-title">FLAGGED SIGNALS</div>', unsafe_allow_html=True)
                for factor in result.get("risk_factors", []) or ["No explicit risk factors identified"]:
                    st.markdown(f'<div class="risk-item">{html.escape(str(factor))}</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
            with st.expander("Why Sentinel reached this conclusion"): st.write(result.get("reasoning", "No reasoning provided."))

with tab2:
    st.markdown('<div class="glass"><div class="eyebrow">02 / Validate engine</div><h3 style="margin:4px 0 8px;">Evaluate against your dataset</h3><p style="color:#91a7bd;margin-top:0;">Upload a CSV containing <code>text</code> (or <code>message_text</code>) and <code>label</code> columns.</p>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Choose a CSV dataset", type=["csv"])
    st.markdown('</div>', unsafe_allow_html=True)
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            text_col = "text" if "text" in df.columns else "message_text" if "message_text" in df.columns else None
            if text_col is None or "label" not in df.columns: st.error("Your CSV needs a 'text' (or 'message_text') column and a 'label' column.")
            else:
                st.success(f"Dataset verified — {len(df):,} messages ready for evaluation.")
                with st.expander("Preview dataset"):
                    st.dataframe(df, use_container_width=True, height=300)
                limit = st.number_input("Messages to evaluate", min_value=1, max_value=len(df), value=min(50, len(df)))
                if st.button("Run evaluation  →", type="primary"):
                    with st.spinner("Processing messages in batches..."):
                        results = evaluate_model(df["label"].tolist()[:limit], [item["label"] for item in detector.detect_batch(df[text_col].tolist()[:limit])])
                    st.success("Evaluation complete")
                    a, b, c = st.columns(3); a.metric("Overall accuracy", f"{results['overall_accuracy']}%"); b.metric("Messages scanned", results["total_predictions"]); c.metric("Correct predictions", results["correct_predictions"])
                    st.info(results["summary"])
        except Exception as exc: st.error(f"Could not load this dataset: {exc}")
