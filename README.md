# TraceLab — Digital Crime Scene Reconstructor

A beginner-friendly Streamlit cybersecurity project for educational phishing triage and digital incident reporting.

## Features
- URL heuristic checks (never opens or fetches URLs)
- Suspicious wording indicators for pasted messages
- Explainable URL, message, and combined scores
- Generated investigation workflow timeline
- Evidence relationship view
- Downloadable JSON and TXT case reports
- Session dashboard and CSV export

## Run locally
Python 3.10 or newer is recommended.

```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
1. Upload `app.py`, `requirements.txt`, and `README.md` to your GitHub repository.
2. Create an app in Streamlit Community Cloud using that repository.
3. Set the main file path to `app.py`.

## Scoring
- URL indicator weights are added and capped at 100.
- Each distinct suspicious phrase adds 5 message points, capped at 30.
- Combined score is URL score plus message points, capped at 100.
- Low: 0–19; Medium: 20–44; High: 45–100.

## Safety and limitations
This is educational, rule-based triage—not a definitive detector or forensic tool. Scores are not probabilities. A low score does not guarantee safety. The app does not visit URLs, use live threat-intelligence feeds, or prove an attack occurred. Session history is temporary. Use fictional or sanitized data; never enter passwords or private tokens.
