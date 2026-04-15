# ScamShield Layer 3 — Technical Design

## Architecture

```
Scammer's phone
      │  PSTN call
      ▼
Twilio virtual number
      │  HTTP POST webhook (TwiML)
      ▼
Flask app on Render  ──► Groq API (Llama 3)
      │
      │  in-memory list
      ▼
REST API  ◄── Browser dashboard (polling every 2 s)
```

All audio stays within Twilio's infrastructure. The Flask app only ever receives plain-text transcripts. The user's mobile phone is never in the data path.

---

## File structure

```
scamshield-kiro/
├── scamshield.py          # entire application — single file
├── requirements.txt       # Python dependencies
├── .env.example           # template for environment variables
├── render.yaml            # Render deployment config
└── .kiro/
    └── specs/
        └── scamshield/
            ├── requirements.md
            ├── design.md
            └── tasks.md
```

---

## scamshield.py — module layout

The file is organised into clearly commented sections:

```python
# ── 1. IMPORTS & CONFIG ──────────────────────────────────────────────
# ── 2. IN-MEMORY STORE ───────────────────────────────────────────────
# ── 3. KEYWORD LIBRARY ───────────────────────────────────────────────
# ── 4. ANALYSIS ENGINE ───────────────────────────────────────────────
# ── 5. TWILIO WEBHOOKS ───────────────────────────────────────────────
# ── 6. REST API ──────────────────────────────────────────────────────
# ── 7. DASHBOARD HTML (inline string) ────────────────────────────────
# ── 8. ENTRY POINT ───────────────────────────────────────────────────
```

---

## Section 1 — Imports & config

```python
import os, json, time, re, threading
from datetime import datetime
from flask import Flask, request, jsonify, Response
from twilio.twiml.voice_response import VoiceResponse, Gather
import requests   # used for Groq HTTP call (no SDK dependency)

app = Flask(__name__)

GROQ_API_KEY      = os.getenv("GROQ_API_KEY", "")
BASE_URL          = os.getenv("BASE_URL", "http://localhost:5000")
PORT              = int(os.getenv("PORT", 5000))
GROQ_MODEL        = "llama3-70b-8192"
GROQ_ENDPOINT     = "https://api.groq.com/openai/v1/chat/completions"
```

---

## Section 2 — In-memory store

```python
alerts = []          # list of alert dicts, appended on each call
alerts_lock = threading.Lock()

def upsert_alert(call_sid: str, patch: dict) -> dict:
    """Create or update an alert for call_sid. Thread-safe."""
    with alerts_lock:
        for a in alerts:
            if a["call_sid"] == call_sid:
                a.update(patch)
                return a
        alert = {
            "call_sid": call_sid,
            "caller_number": "unknown",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "transcripts": [],
            "keyword_hits": [],
            "llm_result": {},
            "threat_score": 0,
            "verdict": "LOW",
        }
        alert.update(patch)
        alerts.insert(0, alert)
        return alert
```

---

## Section 3 — Keyword library

Define `KEYWORDS: list[dict]` where each entry has `phrase` (str), `weight` (int 1–3), and `category` (str). Categories: `urgency`, `data_request`, `impersonation`, `social_engineering`.

Must include at minimum (but expand to 40+):

- urgency: "account blocked", "last chance", "immediate action", "within 24 hours", "suspended", "expired", "final notice", "limited time", "act now", "urgent"
- data_request: "otp", "one time password", "cvv", "pin number", "social security", "aadhaar", "pan number", "account number", "password", "credit card number", "bank details", "upi pin"
- impersonation: "rbi", "income tax", "irs", "bank of", "tech support", "microsoft", "amazon", "government official", "police", "customs"
- social_engineering: "verify your identity", "confirm your details", "security check", "don't tell anyone", "keep this confidential", "press 1", "stay on the line"

```python
def scan_keywords(text: str) -> tuple[list[str], int]:
    """Return (matched_phrases, raw_keyword_score)."""
    text_lower = text.lower()
    hits, score = [], 0
    for kw in KEYWORDS:
        if kw["phrase"] in text_lower:
            hits.append(kw["phrase"])
            score += kw["weight"]
    return hits, score
```

---

## Section 4 — Analysis engine

### Groq LLM call

```python
GROQ_SYSTEM_PROMPT = """
You are a vishing (voice phishing) detection AI.
Analyse the caller's response and return ONLY valid JSON with these keys:
- intent_label: "safe" | "suspicious" | "malicious"
- confidence: float 0.0–1.0
- detected_tactics: array of short strings (max 5)
- reasoning: one sentence

Do not include any text outside the JSON object.
"""

def call_groq(transcript: str) -> dict:
    try:
        resp = requests.post(
            GROQ_ENDPOINT,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": GROQ_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Caller said: {transcript}"}
                ],
                "max_tokens": 300,
                "temperature": 0.1,
            },
            timeout=8,
        )
        raw = resp.json()["choices"][0]["message"]["content"].strip()
        return json.loads(raw)
    except Exception as e:
        return {"intent_label": "safe", "confidence": 0.0, "detected_tactics": [], "reasoning": str(e)}
```

### Threat score formula

```python
def calculate_score(keyword_score: int, llm_result: dict) -> tuple[int, str]:
    confidence = llm_result.get("confidence", 0.0)
    tactic_count = len(llm_result.get("detected_tactics", []))
    score = min(100, keyword_score * 8 + int(confidence * 40) + tactic_count * 5)
    if score >= 70:
        verdict = "HIGH"
    elif score >= 40:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"
    return score, verdict
```

---

## Section 5 — Twilio webhooks

Four Flask routes handle the call lifecycle:

### POST /voice — initial greeting

```python
@app.route("/voice", methods=["POST"])
def voice():
    call_sid = request.form.get("CallSid", "unknown")
    caller   = request.form.get("From", "unknown")
    upsert_alert(call_sid, {"caller_number": caller})

    r = VoiceResponse()
    r.say("Hello. You have reached ScamShield security screening. "
          "Please answer a few questions to connect your call.", voice="Polly.Joanna")
    gather = Gather(input="speech", action=f"{BASE_URL}/answer/1",
                    method="POST", speech_timeout="auto", language="en-IN")
    gather.say("Question one. What is the purpose of your call today?", voice="Polly.Joanna")
    r.append(gather)
    return Response(str(r), mimetype="text/xml")
```

### POST /answer/<int:question_num>

Handle questions 1–4 in a loop. After question 4 (or if threat score ≥ 70 at any point), run full analysis and either hang up or say "Thank you, connecting you now." and `<Hangup>`.

Questions array (defined at module level):
```python
QUESTIONS = [
    "What is the purpose of your call today?",
    "Can you verify your identity and the organisation you represent?",
    "Is this a time-sensitive or urgent matter?",
    "Will you need me to share any account details, OTP, or personal information?",
]
```

For each answer:
1. Append transcript to alert
2. Run `scan_keywords`
3. Run `call_groq` in a `threading.Thread` (non-blocking, store result when done)
4. If current cumulative score ≥ 70 → terminate immediately
5. Else if more questions remain → ask next question
6. Else → final verdict, hang up if HIGH, connect if LOW/MEDIUM

### POST /status — call status callback

```python
@app.route("/status", methods=["POST"])
def status():
    # Twilio posts final call status here. Log it, no TwiML response needed.
    return "", 204
```

---

## Section 6 — REST API

```python
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response

app.after_request(security_headers)

@app.route("/api/alerts")
def api_alerts():
    with alerts_lock:
        return jsonify(list(alerts))   # already newest-first

@app.route("/api/alerts/<call_sid>")
def api_alert(call_sid):
    with alerts_lock:
        for a in alerts:
            if a["call_sid"] == call_sid:
                return jsonify(a)
    return jsonify({"error": "not found"}), 404

@app.route("/api/metrics")
def api_metrics():
    with alerts_lock:
        total = len(alerts)
        high  = sum(1 for a in alerts if a["verdict"] == "HIGH")
        med   = sum(1 for a in alerts if a["verdict"] == "MEDIUM")
        low   = sum(1 for a in alerts if a["verdict"] == "LOW")
        avg   = round(sum(a["threat_score"] for a in alerts) / total, 1) if total else 0
    return jsonify({"total_calls": total, "high_risk": high, "medium_risk": med,
                    "low_risk": low, "avg_score": avg})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})
```

---

## Section 7 — Dashboard HTML

The dashboard is an inline Python string (triple-quoted) returned by `GET /`. It must be self-contained with no external CSS or JS. Key implementation points:

- Use `setInterval(fetchAlerts, 2000)` to poll `/api/alerts`
- Colour code verdict badges: HIGH = `#dc2626`, MEDIUM = `#d97706`, LOW = `#16a34a`
- Highlight keyword_hits inside transcript text using `<mark>` tags (yellow background)
- Draw a bar chart of the last 10 threat scores using `canvas.getContext("2d")` — bars are red if score ≥ 70, amber if ≥ 40, green otherwise
- Each alert row is clickable; clicking expands a detail panel showing full transcripts, LLM reasoning, and detected tactics
- Dark header bar (`#111827`) with white logo text
- Mobile-responsive: single column on `< 640px` screen width using `@media` query

---

## Section 8 — Entry point

```python
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
```

---

## requirements.txt

```
flask>=3.0.0
twilio>=9.0.0
requests>=2.31.0
python-dotenv>=1.0.0
gunicorn>=21.0.0
```

---

## render.yaml

```yaml
services:
  - type: web
    name: scamshield-layer3
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn scamshield:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60
    envVars:
      - key: GROQ_API_KEY
        sync: false
      - key: TWILIO_ACCOUNT_SID
        sync: false
      - key: TWILIO_AUTH_TOKEN
        sync: false
      - key: TWILIO_PHONE_NUMBER
        sync: false
      - key: BASE_URL
        sync: false
```

---

## .env.example

```
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_PHONE_NUMBER=+1XXXXXXXXXX
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
BASE_URL=https://your-app.onrender.com
PORT=5000
```

---

## Error handling rules

- If Groq times out or returns non-JSON, `call_groq` returns a safe default (confidence 0, no tactics). The call continues normally.
- If a Twilio webhook receives no speech input (empty transcript), skip analysis for that question and ask again once.
- All analysis runs in background threads so TwiML responses are returned to Twilio within the 5-second webhook timeout.
- Never log raw API keys. Log only `call_sid`, `verdict`, and `score`.
