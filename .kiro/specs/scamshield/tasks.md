# ScamShield Layer 3 — Implementation Tasks

## Task list

- [x] 1. Scaffold project files
- [x] 2. Build keyword library
- [x] 3. Implement in-memory store and upsert logic
- [x] 4. Implement Groq LLM caller
- [x] 5. Implement threat score calculator
- [x] 6. Implement Twilio webhook — initial greeting (POST /voice)
- [x] 7. Implement Twilio webhook — answer handler (POST /answer/<n>)
- [x] 8. Implement Twilio webhook — status callback (POST /status)
- [x] 9. Implement REST API endpoints
- [x] 10. Build dashboard HTML with live polling
- [x] 11. Build inline canvas bar chart
- [x] 12. Wire security headers and health check
- [x] 13. Write requirements.txt and render.yaml
- [x] 14. Write .env.example and README setup steps

---

## Task 1 — Scaffold project files

Create the following empty files with correct structure:
- `scamshield.py` with all 8 section comment headers
- `requirements.txt` (populated per design.md)
- `.env.example` (populated per design.md)
- `render.yaml` (populated per design.md)

The Flask `app` object must be importable as `from scamshield import app` so gunicorn can find it.

**Acceptance**: `python -c "from scamshield import app; print(app)"` exits 0.

---

## Task 2 — Build keyword library

Implement the `KEYWORDS` list in Section 3 of `scamshield.py`.

Requirements:
- Minimum 40 entries total across all 4 categories
- Each entry is a dict: `{"phrase": str, "weight": int, "category": str}`
- Weights: 1 = mild indicator, 2 = moderate, 3 = strong red flag
- Include all example phrases listed in design.md plus expand each category to at least 10 entries

Implement `scan_keywords(text: str) -> tuple[list[str], int]` exactly as specified.

**Acceptance**: `scan_keywords("your account is blocked, verify your otp immediately")` returns a hits list containing at least `"account blocked"` and `"otp"`, with score ≥ 4.

---

## Task 3 — In-memory store

Implement `alerts` list, `alerts_lock`, and `upsert_alert(call_sid, patch)` in Section 2.

Requirements:
- `upsert_alert` must use the lock on every read and write
- New alerts are inserted at index 0 (newest first)
- Patch dict is merged with `dict.update()` — existing keys are overwritten, missing keys added
- `transcripts` and `keyword_hits` in patch should be appended (not replaced) — use `extend` when patch key ends with `_append` suffix convention OR handle transcript appending in the webhook layer (either approach is fine, be consistent)

**Acceptance**: Calling `upsert_alert("SID1", {"caller_number": "+91999"})` twice with different patches results in exactly one alert for `SID1`.

---

## Task 4 — Groq LLM caller

Implement `call_groq(transcript: str) -> dict` in Section 4.

Requirements:
- POST to `https://api.groq.com/openai/v1/chat/completions`
- Use `GROQ_SYSTEM_PROMPT` string exactly as specified in design.md — do not paraphrase it
- Set `timeout=8` on the requests call so Twilio's webhook timeout is never exceeded
- Strip markdown code fences before `json.loads()` in case the model wraps output in ` ```json ``` `
- On any exception, return the safe default dict specified in design.md

**Acceptance**: When `GROQ_API_KEY` is unset, `call_groq("test")` returns a dict with key `intent_label` set to `"safe"` without raising.

---

## Task 5 — Threat score calculator

Implement `calculate_score(keyword_score: int, llm_result: dict) -> tuple[int, str]` in Section 4.

Formula (from requirements REQ-6):
```
score = min(100, keyword_score * 8 + int(confidence * 40) + tactic_count * 5)
```

Thresholds: HIGH ≥ 70, MEDIUM ≥ 40, LOW < 40.

**Acceptance**:
- `calculate_score(0, {"confidence": 0.0, "detected_tactics": []})` → `(0, "LOW")`
- `calculate_score(5, {"confidence": 0.9, "detected_tactics": ["urgency", "data request", "impersonation"]})` → score ≥ 70, verdict `"HIGH"`

---

## Task 6 — Twilio webhook: /voice

Implement `POST /voice` in Section 5.

Requirements:
- Extract `CallSid` and `From` from `request.form`
- Call `upsert_alert` to create the alert record
- Return TwiML: `<Say>` greeting → `<Gather input="speech" action="{BASE_URL}/answer/1" speech_timeout="auto" language="en-IN">` containing `<Say>` for question 1
- Use `voice="Polly.Joanna"` on all `<Say>` elements
- Return with `mimetype="text/xml"`

**Acceptance**: POSTing `CallSid=TEST&From=+919999999999` returns valid XML containing `<Gather` and `<Say`.

---

## Task 7 — Twilio webhook: /answer/<n>

Implement `POST /answer/<int:question_num>` in Section 5.

This is the most complex route. Implement it as follows:

1. Extract `CallSid`, `SpeechResult` (transcript), `Confidence` from `request.form`
2. If `SpeechResult` is empty or missing, re-ask the same question (repeat once only — track in alert with `retried_q` set)
3. Append transcript to alert's `transcripts` list
4. Run `scan_keywords(transcript)` — accumulate hits and score into alert
5. Spawn a `threading.Thread` to call `call_groq(transcript)` and update alert with result + recalculate score when thread completes
6. Recalculate score immediately using keyword score only (LLM result may not be ready yet)
7. If accumulated score ≥ 70 → terminate: TwiML `<Say>` "This call has been flagged as high risk and will now be disconnected." then `<Hangup>`
8. Else if `question_num < 4` → ask next question via `<Gather action="{BASE_URL}/answer/{question_num+1}">`
9. Else (question 4 done) → wait up to 3s for LLM thread, recalculate final score, then:
   - HIGH → terminate TwiML
   - MEDIUM → `<Say>` "Thank you. Exercise caution with this call." then `<Hangup>`
   - LOW → `<Say>` "Thank you. Connecting you now." then `<Hangup>`

**Acceptance**: Simulating 4 POST requests with `SpeechResult` values including "otp" and "urgent account blocked" results in a HIGH verdict and termination TwiML by question 3 or 4.

---

## Task 8 — Twilio webhook: /status

Implement `POST /status`. Log call_sid and call_status to stdout. Return 204 No Content.

**Acceptance**: POSTing any form data returns HTTP 204.

---

## Task 9 — REST API endpoints

Implement all four endpoints from Section 6 of design.md:
- `GET /api/alerts` → list of all alerts, newest first
- `GET /api/alerts/<call_sid>` → single alert or 404
- `GET /api/metrics` → summary counts and avg score
- `GET /health` → `{"status": "ok", "version": "1.0.0"}`

Apply `security_headers` via `app.after_request`.

**Acceptance**: All four routes return valid JSON with correct HTTP status codes.

---

## Task 10 — Dashboard HTML with polling

Implement the `DASHBOARD_HTML` string in Section 7 and the `GET /` route that returns it.

The HTML must contain:
- A dark header bar (`background: #111827`) with title "ScamShield — Live Dashboard"
- A metrics bar: 4 `<div>` cards for total calls, high risk, medium risk, avg score — updated by polling `/api/metrics`
- An alerts list `<div id="alerts-list">` populated by polling `/api/alerts` every 2s
- Each alert row shows: caller number, timestamp, verdict badge, threat score pill
- Clicking a row expands a detail panel showing: all transcripts (with keyword hits wrapped in `<mark style="background:#fef08a">`), detected tactics as chips, LLM reasoning text
- A `<canvas id="score-chart" width="600" height="120">` element for the chart
- CSS: mobile-responsive using a single `@media (max-width: 640px)` breakpoint; no external stylesheets
- No `<form>` tags; all interaction via `onclick` handlers

**Acceptance**: Opening the dashboard in a browser while alerts exist shows at least one clickable row.

---

## Task 11 — Canvas bar chart

Inside the dashboard's `<script>` block, implement `drawChart(alerts)` that draws a bar chart on `#score-chart`.

Requirements:
- Show the last 10 alerts (or fewer if less than 10 exist)
- Each bar's height is proportional to `threat_score / 100 * chart_height`
- Bar colour: `#dc2626` if score ≥ 70, `#d97706` if ≥ 40, `#16a34a` if < 40
- Draw a dashed horizontal line at y-position corresponding to score = 70 (HIGH threshold)
- Draw small score labels above each bar
- Re-draw on every poll cycle by calling `ctx.clearRect(0, 0, w, h)` before redrawing

**Acceptance**: Chart renders correctly with at least 3 bars when test data is present.

---

## Task 12 — Security headers and health check

Ensure `app.after_request(security_headers)` is registered exactly once.

Verify these headers appear on API responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Cache-Control: no-store`

**Acceptance**: `curl -I http://localhost:5000/health` shows all three headers.

---

## Task 13 — requirements.txt and render.yaml

Write final versions of both files exactly as specified in design.md.

`requirements.txt` must pin minimum versions (use `>=`, not `==`) for:
- flask, twilio, requests, python-dotenv, gunicorn

`render.yaml` must use gunicorn start command with `--workers 2 --timeout 60`.

**Acceptance**: `pip install -r requirements.txt` completes without error in a fresh Python 3.9+ virtualenv.

---

## Task 14 — .env.example and README

Write `.env.example` with all 6 variables (values as placeholders).

Write a `README.md` with exactly these sections (keep each section brief):
1. **What it does** — 3 sentences max
2. **Tech stack** — table with 5 rows: Twilio, Groq, Render, Flask, Dashboard
3. **Setup in 5 steps**:
   1. Clone repo and `pip install -r requirements.txt`
   2. Copy `.env.example` to `.env` and fill in values
   3. Deploy to Render — set env vars in dashboard
   4. Set Twilio webhook URL to `https://your-app.onrender.com/voice`
   5. Call your Twilio number to test
4. **Dashboard URL** — `https://your-app.onrender.com`
5. **How threat scoring works** — the formula from REQ-6

**Acceptance**: File exists and renders correctly as Markdown.
