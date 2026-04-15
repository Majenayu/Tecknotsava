# ScamShield Layer 3 — Requirements

## Overview
A real-time vishing (voice phishing) detection system. When an unknown caller dials a Twilio virtual number, an AI voice assistant intercepts the call, asks screening questions, analyses responses for scam indicators, calculates a threat score, and displays everything on a live web dashboard. The user's mobile phone only dials the Twilio number — no audio or call data is processed on the device.

---

## Requirements

### REQ-1 — Inbound call interception
**WHEN** an inbound call arrives at the Twilio virtual number,  
**THE SYSTEM SHALL** answer the call using TwiML and play an AI greeting message before prompting the caller.

### REQ-2 — Caller screening questions
**WHEN** the call is answered,  
**THE SYSTEM SHALL** ask the caller four screening questions in sequence using Twilio `<Gather>` with speech input:
1. "What is the purpose of your call today?"
2. "Can you verify your identity and the organisation you represent?"
3. "Is this a time-sensitive or urgent matter?"
4. "Will you need me to share any account details, OTP, or personal information?"

### REQ-3 — Speech to text
**WHEN** the caller speaks a response,  
**THE SYSTEM SHALL** use Twilio's built-in speech recognition (no external STT API) to transcribe the audio and POST the transcript to the Flask webhook.

### REQ-4 — Keyword pattern matching
**WHEN** a transcript is received,  
**THE SYSTEM SHALL** scan it against a library of at least 40 red-flag keywords and phrases covering urgency tactics, data requests, impersonation claims, and social engineering language, and assign a partial threat score.

### REQ-5 — LLM intent analysis
**WHEN** a transcript is received,  
**THE SYSTEM SHALL** call the Groq API (model: llama3-70b-8192) with a system prompt instructing it to return a JSON object containing: `intent_label` (safe / suspicious / malicious), `confidence` (0–1), `detected_tactics` (array of strings), and `reasoning` (one sentence).

### REQ-6 — Threat score calculation
**WHEN** both keyword and LLM results are available,  
**THE SYSTEM SHALL** compute a combined threat score (0–100) using the formula:  
`score = min(100, keyword_hits * 8 + llm_confidence * 40 + tactic_count * 5)`  
and classify it as LOW (0–39), MEDIUM (40–69), or HIGH (70–100).

### REQ-7 — Automatic call termination
**WHEN** the threat score is HIGH (≥ 70),  
**THE SYSTEM SHALL** respond to Twilio with a TwiML `<Say>` warning message followed by `<Hangup>` to terminate the call.

### REQ-8 — In-memory alert storage
**THE SYSTEM SHALL** store each call event as an alert object in a Python list (in-memory) containing: `call_sid`, `caller_number`, `timestamp`, `transcripts` (list), `keyword_hits` (list), `llm_result` (dict), `threat_score` (int), and `verdict` (LOW / MEDIUM / HIGH).

### REQ-9 — REST API for dashboard
**THE SYSTEM SHALL** expose the following JSON endpoints:
- `GET /api/alerts` — returns all stored alerts, newest first
- `GET /api/alerts/<call_sid>` — returns a single alert by call SID
- `GET /api/metrics` — returns `{ total_calls, high_risk, medium_risk, low_risk, avg_score }`

### REQ-10 — Live web dashboard
**THE SYSTEM SHALL** serve a single-file HTML dashboard at `GET /` that:
- Polls `/api/alerts` every 2 seconds using `fetch()`
- Displays a summary metric bar (total calls, high risk count, avg threat score)
- Renders a colour-coded alert list (red = HIGH, amber = MEDIUM, green = LOW)
- Shows a live transcript panel and highlighted red-flag keywords on click
- Requires no login, no external JS frameworks, no CDN dependencies

### REQ-11 — Threat score chart
**WHEN** the dashboard is open,  
**THE SYSTEM SHALL** render a real-time bar chart of the last 10 threat scores using an inline `<canvas>` element drawn with vanilla Canvas 2D API (no Chart.js or external library).

### REQ-12 — Environment configuration
**THE SYSTEM SHALL** read all secrets exclusively from environment variables:
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_PHONE_NUMBER`
- `GROQ_API_KEY`
- `BASE_URL` (public Render URL, used for Twilio webhook registration)
- `PORT` (default 5000)

### REQ-13 — Single-file deployment
**THE SYSTEM SHALL** run from a single Python file `scamshield.py` with no compiled assets, no database migrations, and no build step, so it can be deployed to Render by pointing to `python scamshield.py`.

### REQ-14 — CORS and security headers
**THE SYSTEM SHALL** add `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Cache-Control: no-store` headers to all API responses.

### REQ-15 — Health check endpoint
**THE SYSTEM SHALL** expose `GET /health` returning `{ "status": "ok", "version": "1.0.0" }` so Render and UptimeRobot can keep the instance warm.
