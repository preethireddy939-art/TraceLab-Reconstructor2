"""TraceLab: educational, local-only digital incident triage with Streamlit."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(page_title="TraceLab | Digital Crime Scene Reconstructor", page_icon="🕵️", layout="wide")

SUSPICIOUS_WORDS = [
    "verify", "urgent", "password", "login", "account suspended", "payment",
    "invoice", "gift card", "confirm", "security alert", "limited time", "reset", "bank",
    "click here", "winner", "prize", "immediately", "unusual activity",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at", "rb.gy", "ow.ly"}
RISK_BANDS = ((45, "High"), (20, "Medium"), (0, "Low"))
LIMITATIONS = [
    "This is educational heuristic triage, not a definitive verdict or probability.",
    "TraceLab does not visit, fetch, or open submitted URLs.",
    "A low score does not mean a URL or message is safe; false positives and false negatives are possible.",
    "The timeline describes investigation workflow, not verified attacker actions.",
]

if "cases" not in st.session_state:
    st.session_state.cases = []
if "latest_case" not in st.session_state:
    st.session_state.latest_case = None


def risk_level(score: int) -> str:
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def normalize_url(raw_url: str) -> str:
    """Prepare a string for parsing; this function never makes a network request."""
    value = (raw_url or "").strip()
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value


def analyze_url(raw_url: str) -> dict:
    original = (raw_url or "").strip()
    if not original:
        return {"url": "", "score": 0, "level": "Not assessed", "findings": [], "host": ""}

    candidate = normalize_url(original)
    findings: list[dict] = []
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        # Accessing .port can raise ValueError for malformed ports; validate safely.
        _ = parsed.port
    except ValueError:
        parsed = None
        host = ""
        findings.append({"points": 18, "indicator": "Malformed URL", "explanation": "The address has a parsing problem. Check its format and port."})

    if parsed is not None:
        if not host:
            findings.append({"points": 18, "indicator": "Hostname missing", "explanation": "TraceLab could not identify a hostname in this input."})
        if parsed.scheme.lower() not in {"http", "https"}:
            findings.append({"points": 12, "indicator": "Unusual URL scheme", "explanation": "The address does not use the usual HTTP or HTTPS web scheme."})
        elif parsed.scheme.lower() == "http":
            findings.append({"points": 8, "indicator": "HTTP without HTTPS", "explanation": "The URL uses HTTP. This alone does not prove maliciousness."})
        if host:
            try:
                ipaddress.ip_address(host)
                findings.append({"points": 18, "indicator": "IP address used as host", "explanation": "The host is an IP address rather than a typical domain name; this can be legitimate but deserves review."})
            except ValueError:
                pass
            if host in SHORTENERS:
                findings.append({"points": 12, "indicator": "Link-shortening domain", "explanation": "The final destination is not visible from the shortened link alone."})
            if "xn--" in host:
                findings.append({"points": 16, "indicator": "Punycode in domain", "explanation": "The domain contains an internationalized-domain encoding that deserves review."})
            if host.count(".") >= 4:
                findings.append({"points": 10, "indicator": "Many subdomain levels", "explanation": "The host contains several subdomain levels; inspect the registered domain carefully."})
            if any(token in host for token in ("secure-login", "account-verify", "password-reset", "signin-check")):
                findings.append({"points": 18, "indicator": "Login/verification wording in host", "explanation": "The hostname contains wording often used in account-lure links."})
        if "@" in parsed.netloc:
            findings.append({"points": 15, "indicator": "At-sign in URL authority", "explanation": "An at-sign in this part of a URL can make the apparent destination confusing."})
        if len(candidate) > 120:
            findings.append({"points": 8, "indicator": "Unusually long URL", "explanation": "Long addresses can hide confusing paths or parameters."})
        if re.search(r"%[0-9a-fA-F]{2}", candidate):
            findings.append({"points": 5, "indicator": "Percent-encoded characters", "explanation": "The URL contains encoded characters; this is common but can reduce readability."})

    score = min(100, sum(item["points"] for item in findings))
    return {"url": candidate, "score": score, "level": risk_level(score), "findings": findings, "host": host}


def analyze_message(message: str) -> list[str]:
    """Return distinct configured phrase matches, not every repeated occurrence."""
    text = (message or "").casefold()
    return [phrase for phrase in SUSPICIOUS_WORDS if phrase in text]


def build_case(case_id: str, analyst: str, incident_type: str, url_text: str, message: str, notes: str) -> dict:
    url_result = analyze_url(url_text)
    message_hits = analyze_message(message)
    message_points = min(30, len(message_hits) * 5)
    combined_score = min(100, url_result["score"] + message_points)
    created_at = datetime.now().astimezone().isoformat(timespec="seconds")
    timeline = [{"stage": "Report received", "status": "Input recorded", "detail": "Incident details were entered into TraceLab."}]
    if (message or "").strip():
        timeline.append({"stage": "Message reviewed", "status": "Local text checks", "detail": f"{len(message_hits)} configured suspicious wording pattern(s) matched."})
    if (url_text or "").strip():
        timeline.append({"stage": "URL triaged", "status": "Local string analysis", "detail": f"{len(url_result['findings'])} configured URL indicator(s) found. Host: {url_result['host'] or 'not identified'}."})
    timeline.append({"stage": "Analyst review", "status": "Recommended next step", "detail": "Verify the sender and destination through an independent trusted channel and preserve original evidence."})
    return {
        "case_id": case_id, "created_at": created_at, "analyst": (analyst or "").strip() or "Not specified",
        "incident_type": incident_type, "url": url_result, "message_indicators": message_hits,
        "message_score": message_points, "combined_score": combined_score, "risk_level": risk_level(combined_score),
        "notes": (notes or "").strip(), "timeline": timeline, "limitations": LIMITATIONS,
    }


def make_txt_report(case: dict) -> str:
    lines = [
        "TRACELAB DIGITAL INCIDENT TRIAGE REPORT", "=" * 40,
        f"Case ID: {case['case_id']}", f"Created: {case['created_at']}",
        f"Analyst: {case['analyst']}", f"Category: {case['incident_type']}",
        f"URL score: {case['url']['score']}/100", f"Message points: {case['message_score']}/30",
        f"Combined heuristic score: {case['combined_score']}/100", f"Triage level: {case['risk_level']}",
        "", "URL findings:",
    ]
    if case["url"]["findings"]:
        lines.extend(f"- +{x['points']} {x['indicator']}: {x['explanation']}" for x in case["url"]["findings"])
    else:
        lines.append("- No configured URL indicators matched, or no URL was supplied.")
    lines += ["", "Message indicators: " + (", ".join(case["message_indicators"]) or "None matched / no message supplied"), "", "Investigator notes:", case["notes"] or "None", "", "Workflow timeline:"]
    lines.extend(f"- {x['stage']} ({x['status']}): {x['detail']}" for x in case["timeline"])
    lines += ["", "Limitations:"] + ["- " + item for item in case["limitations"]]
    return "\n".join(lines)


st.markdown("""<style>
.block-container{padding-top:1.3rem;max-width:1200px}
.hero{padding:1.3rem 1.4rem;border-radius:16px;background:linear-gradient(120deg,#102735,#153e4a);color:#f4fbff;border:1px solid #2b5a64;margin-bottom:1rem}
.hero h1{margin:0 0 .25rem 0;font-size:2rem}.hero p{margin:0;color:#c6e3e8}
.evidence{border:1px solid rgba(128,128,128,.28);border-radius:12px;padding:12px;margin:8px 0}
</style>""", unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>🕵️ TraceLab</h1><p>Digital Crime Scene Reconstructor · Connect evidence, review indicators, and create a structured incident report.</p></div>', unsafe_allow_html=True)
st.warning("Safety boundary: TraceLab never opens or visits submitted URLs. Scores are explainable heuristics, not proof that content is malicious or safe.")

with st.sidebar:
    st.header("Investigation workspace")
    st.write("Use fictional or sanitized examples. Never paste passwords, private tokens, or sensitive personal data.")
    st.metric("Cases this session", len(st.session_state.cases))
    if st.button("Clear session history", use_container_width=True):
        st.session_state.cases = []
        st.session_state.latest_case = None
        st.rerun()
    st.caption("History is temporary and may be lost when the session ends or refreshes.")

page = st.radio("Workspace", ["New investigation", "Case dashboard", "How it works"], horizontal=True, label_visibility="collapsed")

if page == "New investigation":
    left, right = st.columns([1.05, .95], gap="large")
    with left:
        st.subheader("1 · Record the incident")
        with st.form("case_form", clear_on_submit=False):
            analyst = st.text_input("Analyst / student name (optional)", placeholder="e.g., Student Investigator")
            incident_type = st.selectbox("Incident category", ["Suspected phishing", "Suspicious message", "Account impersonation", "Payment scam", "Unknown / other"])
            url_text = st.text_input("Suspicious URL (optional)", placeholder="example.com/login")
            message = st.text_area("Message or incident text (optional)", height=140, placeholder="Paste a sanitized suspicious message here…")
            notes = st.text_area("Investigator notes", height=90, placeholder="Where was it reported? What is verified? What remains unknown?")
            submitted = st.form_submit_button("Reconstruct digital crime scene", type="primary", use_container_width=True)
        if submitted:
            if not any(x.strip() for x in (url_text, message, notes)):
                st.error("Add at least a URL, message text, or investigator note before creating a case.")
            else:
                case_id = "TL-" + datetime.now().astimezone().strftime("%y%m%d-%H%M%S-%f")
                case = build_case(case_id, analyst, incident_type, url_text, message, notes)
                st.session_state.cases.insert(0, case)
                st.session_state.latest_case = case
                st.success(f"Investigation created: {case_id}")
    with right:
        st.subheader("2 · Evidence principles")
        st.markdown("""
        <div class="evidence"><b>🔎 Observe</b><br>Record supplied URL, wording, source, and context.</div>
        <div class="evidence"><b>🧩 Correlate</b><br>Connect each finding to the evidence that triggered it.</div>
        <div class="evidence"><b>⏱ Reconstruct</b><br>Build a workflow timeline without inventing attacker actions.</div>
        <div class="evidence"><b>🛡 Recommend</b><br>Preserve evidence and verify through a separate trusted channel.</div>
        """, unsafe_allow_html=True)
        st.info("A real investigation separates observed evidence, automated indicators, and hypotheses.")

    case = st.session_state.latest_case
    if case:
        st.divider()
        st.subheader("3 · Reconstructed case")
        a, b, c = st.columns(3)
        a.metric("Case ID", case["case_id"])
        b.metric("Combined score", f"{case['combined_score']}/100")
        c.metric("Triage level", case["risk_level"])
        st.caption(f"Created: {case['created_at']} · Category: {case['incident_type']}")
        tab1, tab2, tab3, tab4 = st.tabs(["Evidence findings", "Workflow timeline", "Relationship map", "Export report"])
        with tab1:
            st.markdown("**URL indicators**")
            if case["url"]["url"]:
                st.code(case["url"]["url"], language=None)
                if case["url"]["findings"]:
                    for item in case["url"]["findings"]:
                        with st.container(border=True):
                            st.markdown(f"**+{item['points']} · {item['indicator']}**")
                            st.write(item["explanation"])
                else:
                    st.success("No configured URL warning indicators matched. This does not establish safety.")
            else:
                st.write("No URL supplied.")
            st.markdown(f"**URL score:** {case['url']['score']}/100")
            st.markdown(f"**Message points:** {case['message_score']}/30")
            st.markdown("**Message wording indicators**")
            st.write(", ".join(case["message_indicators"]) if case["message_indicators"] else "No configured wording patterns matched, or no message was supplied.")
            if case["notes"]:
                st.markdown("**Investigator notes**")
                st.write(case["notes"])
        with tab2:
            for i, event in enumerate(case["timeline"], 1):
                with st.container(border=True):
                    st.markdown(f"**{i}. {event['stage']}** · {event['status']}")
                    st.write(event["detail"])
            st.caption("This is a workflow timeline generated from entered information, not a verified timeline of attacker actions.")
        with tab3:
            st.markdown("**Evidence relationship map**")
            nodes = ["Incident report"]
            if case["message_indicators"]:
                nodes.append("Message wording indicators")
            if case["url"]["url"]:
                nodes.append("Submitted URL")
            nodes.append("Heuristic triage assessment")
            cols = st.columns(len(nodes))
            for idx, label in enumerate(nodes):
                with cols[idx]:
                    st.markdown(f"<div class='evidence' style='min-height:95px;display:flex;align-items:center;justify-content:center;text-align:center;font-weight:600'>{label}</div>", unsafe_allow_html=True)
                if idx < len(nodes) - 1:
                    st.caption("→")
            st.caption("Connections show the app's analysis workflow, not causation or proof of a crime.")
        with tab4:
            st.download_button("Download full JSON case file", json.dumps(case, indent=2, ensure_ascii=False), file_name=f"{case['case_id']}.json", mime="application/json", use_container_width=True)
            st.download_button("Download readable TXT report", make_txt_report(case), file_name=f"{case['case_id']}_report.txt", mime="text/plain", use_container_width=True)

elif page == "Case dashboard":
    st.subheader("Investigation dashboard")
    cases = st.session_state.cases
    if not cases:
        st.info("No cases in this session yet. Create a new investigation first.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("Total cases", len(cases))
        c2.metric("High triage", sum(x["risk_level"] == "High" for x in cases))
        c3.metric("URLs reviewed", sum(bool(x["url"]["url"]) for x in cases))
        for case in cases:
            with st.expander(f"{case['case_id']} · {case['incident_type']} · {case['risk_level']} ({case['combined_score']}/100)"):
                st.write(f"Created: {case['created_at']} · Analyst: {case['analyst']}")
                st.write("URL host:", case["url"]["host"] or "Not provided")
                st.download_button("Download this case JSON", json.dumps(case, indent=2, ensure_ascii=False), file_name=f"{case['case_id']}.json", mime="application/json", key="json_" + case["case_id"])
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["case_id", "created_at", "analyst", "incident_type", "url", "url_score", "message_score", "combined_score", "risk_level", "message_indicators", "notes"])
        for item in cases:
            writer.writerow([item["case_id"], item["created_at"], item["analyst"], item["incident_type"], item["url"]["url"], item["url"]["score"], item["message_score"], item["combined_score"], item["risk_level"], "; ".join(item["message_indicators"]), item["notes"]])
        st.download_button("Export session dashboard as CSV", output.getvalue(), file_name="tracelab_cases.csv", mime="text/csv")
        st.caption("Session history is temporary. Download reports before closing or refreshing the session.")

else:
    st.subheader("How TraceLab works")
    st.markdown("""
    1. **Input:** enter a URL, sanitized message, and/or investigator notes.
    2. **Local checks:** URL patterns and suspicious wording are checked as strings. No network requests are made.
    3. **Evidence correlation:** findings remain connected to their source type and explanation.
    4. **Workflow reconstruction:** a timeline and simple relationship view are generated from the supplied details.
    5. **Reporting:** download JSON/TXT reports or export the session dashboard to CSV.

    **Scoring rules:** URL indicators have fixed weights; the URL score is capped at 100. Each distinct suspicious phrase adds 5 message points, capped at 30. Combined score = URL score + message points, capped at 100. Low = 0–19, Medium = 20–44, High = 45–100.

    **Limitations:** this is rule-based, not machine learning. It does not use live reputation databases, inspect website contents, trace attackers, or prove an attack happened. HTTPS alone does not mean a site is safe.
    """)
    st.subheader("Safe demonstration sample")
    st.write("Use this documentation-only sample and a fictional message. The app will analyse the text only.")
    st.code("http://192.0.2.10/secure-login?verify=1\nUrgent: verify your account password now", language=None)

st.divider()
st.caption("TraceLab · Student cybersecurity project · Local heuristic analysis · Submitted URLs are never visited")
