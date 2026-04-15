# ── 1. IMPORTS & CONFIG ──────────────────────────────────────────────
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

QUESTIONS = [
    "What is the purpose of your call today?",
    "Can you verify your identity and the organisation you represent?",
    "Is this a time-sensitive or urgent matter?",
    "Will you need me to share any account details, OTP, or personal information?",
]

# ── 2. IN-MEMORY STORE ───────────────────────────────────────────────

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

# ── 3. KEYWORD LIBRARY ───────────────────────────────────────────────

KEYWORDS = [
    # urgency category
    {"phrase": "account blocked", "weight": 3, "category": "urgency"},
    {"phrase": "account is blocked", "weight": 3, "category": "urgency"},
    {"phrase": "blocked account", "weight": 3, "category": "urgency"},
    {"phrase": "last chance", "weight": 3, "category": "urgency"},
    {"phrase": "immediate action", "weight": 3, "category": "urgency"},
    {"phrase": "within 24 hours", "weight": 2, "category": "urgency"},
    {"phrase": "suspended", "weight": 3, "category": "urgency"},
    {"phrase": "expired", "weight": 2, "category": "urgency"},
    {"phrase": "final notice", "weight": 3, "category": "urgency"},
    {"phrase": "limited time", "weight": 2, "category": "urgency"},
    {"phrase": "act now", "weight": 3, "category": "urgency"},
    {"phrase": "urgent", "weight": 2, "category": "urgency"},
    {"phrase": "emergency", "weight": 3, "category": "urgency"},
    {"phrase": "time sensitive", "weight": 2, "category": "urgency"},
    
    # data_request category
    {"phrase": "otp", "weight": 3, "category": "data_request"},
    {"phrase": "one time password", "weight": 3, "category": "data_request"},
    {"phrase": "cvv", "weight": 3, "category": "data_request"},
    {"phrase": "pin number", "weight": 3, "category": "data_request"},
    {"phrase": "social security", "weight": 3, "category": "data_request"},
    {"phrase": "aadhaar", "weight": 3, "category": "data_request"},
    {"phrase": "pan number", "weight": 3, "category": "data_request"},
    {"phrase": "account number", "weight": 3, "category": "data_request"},
    {"phrase": "password", "weight": 3, "category": "data_request"},
    {"phrase": "credit card number", "weight": 3, "category": "data_request"},
    {"phrase": "bank details", "weight": 3, "category": "data_request"},
    {"phrase": "upi pin", "weight": 3, "category": "data_request"},
    {"phrase": "debit card", "weight": 2, "category": "data_request"},
    {"phrase": "card details", "weight": 3, "category": "data_request"},
    
    # impersonation category
    {"phrase": "rbi", "weight": 3, "category": "impersonation"},
    {"phrase": "income tax", "weight": 3, "category": "impersonation"},
    {"phrase": "irs", "weight": 3, "category": "impersonation"},
    {"phrase": "bank of", "weight": 2, "category": "impersonation"},
    {"phrase": "tech support", "weight": 2, "category": "impersonation"},
    {"phrase": "microsoft", "weight": 2, "category": "impersonation"},
    {"phrase": "amazon", "weight": 2, "category": "impersonation"},
    {"phrase": "government official", "weight": 3, "category": "impersonation"},
    {"phrase": "police", "weight": 3, "category": "impersonation"},
    {"phrase": "customs", "weight": 3, "category": "impersonation"},
    {"phrase": "federal agent", "weight": 3, "category": "impersonation"},
    {"phrase": "tax department", "weight": 3, "category": "impersonation"},
    
    # social_engineering category
    {"phrase": "verify your identity", "weight": 2, "category": "social_engineering"},
    {"phrase": "confirm your details", "weight": 2, "category": "social_engineering"},
    {"phrase": "security check", "weight": 2, "category": "social_engineering"},
    {"phrase": "don't tell anyone", "weight": 3, "category": "social_engineering"},
    {"phrase": "keep this confidential", "weight": 3, "category": "social_engineering"},
    {"phrase": "press 1", "weight": 2, "category": "social_engineering"},
    {"phrase": "stay on the line", "weight": 2, "category": "social_engineering"},
    {"phrase": "do not hang up", "weight": 3, "category": "social_engineering"},
    {"phrase": "follow my instructions", "weight": 3, "category": "social_engineering"},
    {"phrase": "trust me", "weight": 2, "category": "social_engineering"},
    {"phrase": "this is legitimate", "weight": 2, "category": "social_engineering"},
    {"phrase": "authorized representative", "weight": 2, "category": "social_engineering"},
]

def scan_keywords(text: str) -> tuple[list[str], int]:
    """Return (matched_phrases, raw_keyword_score)."""
    text_lower = text.lower()
    hits, score = [], 0
    for kw in KEYWORDS:
        if kw["phrase"] in text_lower:
            hits.append(kw["phrase"])
            score += kw["weight"]
    return hits, score

# ── 4. ANALYSIS ENGINE ───────────────────────────────────────────────

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
    """Call Groq API to analyze transcript. Returns safe default on error."""
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
        # Strip markdown code fences if present
        if raw.startswith("```json"):
            raw = raw[7:]
        if raw.endswith("```"):
            raw = raw[:-3]
        return json.loads(raw.strip())
    except Exception as e:
        print(f"[SCAMSHIELD] ERROR Groq API call failed: {e}")
        return {"intent_label": "safe", "confidence": 0.0, "detected_tactics": [], "reasoning": str(e)}

def calculate_score(keyword_score: int, llm_result: dict) -> tuple[int, str]:
    """Calculate threat score and verdict from keyword and LLM analysis."""
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

# ── 5. TWILIO WEBHOOKS ───────────────────────────────────────────────

@app.route("/voice", methods=["POST"])
def voice():
    """Initial call greeting and first question."""
    call_sid = request.form.get("CallSid", "unknown")
    caller = request.form.get("From", "unknown")
    
    print(f"[SCAMSHIELD] INFO New call from {caller}, SID: {call_sid}")
    upsert_alert(call_sid, {"caller_number": caller})

    r = VoiceResponse()
    r.say("Hello. You have reached ScamShield security screening. "
          "Please answer a few questions to connect your call.", voice="Polly.Joanna")
    gather = Gather(input="speech", action=f"{BASE_URL}/answer/1",
                    method="POST", speech_timeout="auto", language="en-IN")
    gather.say("Question one. What is the purpose of your call today?", voice="Polly.Joanna")
    r.append(gather)
    return Response(str(r), mimetype="text/xml")

def analyze_transcript_async(call_sid: str, transcript: str):
    """Background thread to analyze transcript with Groq."""
    llm_result = call_groq(transcript)
    
    # Update alert with LLM result and recalculate score
    with alerts_lock:
        for alert in alerts:
            if alert["call_sid"] == call_sid:
                alert["llm_result"] = llm_result
                # Recalculate score with both keyword and LLM data
                keyword_score = sum(kw["weight"] for kw in KEYWORDS 
                                  for hit in alert["keyword_hits"] 
                                  if kw["phrase"] == hit)
                score, verdict = calculate_score(keyword_score, llm_result)
                alert["threat_score"] = score
                alert["verdict"] = verdict
                print(f"[SCAMSHIELD] INFO Updated {call_sid} with LLM result: {verdict} ({score})")
                break

@app.route("/answer/<int:question_num>", methods=["POST"])
def answer(question_num):
    """Handle caller responses to screening questions."""
    call_sid = request.form.get("CallSid", "unknown")
    transcript = request.form.get("SpeechResult", "").strip()
    confidence = request.form.get("Confidence", "0")
    
    print(f"[SCAMSHIELD] INFO Q{question_num} response from {call_sid}: {transcript}")
    
    # Handle empty transcript - retry once
    if not transcript:
        alert = upsert_alert(call_sid, {})
        if alert.get("retried_q") == question_num:
            # Already retried this question, move to next
            if question_num < 4:
                question_num += 1
            else:
                # End call
                r = VoiceResponse()
                r.say("Thank you. Connecting you now.", voice="Polly.Joanna")
                r.hangup()
                return Response(str(r), mimetype="text/xml")
        else:
            # Retry same question
            upsert_alert(call_sid, {"retried_q": question_num})
            r = VoiceResponse()
            gather = Gather(input="speech", action=f"{BASE_URL}/answer/{question_num}",
                          method="POST", speech_timeout="auto", language="en-IN")
            gather.say(f"I didn't catch that. {QUESTIONS[question_num-1]}", voice="Polly.Joanna")
            r.append(gather)
            return Response(str(r), mimetype="text/xml")
    
    # Analyze transcript
    hits, keyword_score = scan_keywords(transcript)
    
    # Get current alert and update with new transcript and hits
    alert = upsert_alert(call_sid, {})
    current_transcripts = alert.get("transcripts", [])
    current_hits = alert.get("keyword_hits", [])
    
    # Update alert with new data
    upsert_alert(call_sid, {
        "transcripts": current_transcripts + [transcript],
        "keyword_hits": current_hits + hits
    })
    
    # Start LLM analysis in background
    threading.Thread(target=analyze_transcript_async, args=(call_sid, transcript), daemon=True).start()
    
    # Get updated alert for score calculation
    alert = upsert_alert(call_sid, {})
    
    # Calculate immediate score based on keywords only
    total_keyword_score = sum(kw["weight"] for kw in KEYWORDS 
                            for hit in alert["keyword_hits"] 
                            if kw["phrase"] == hit)
    immediate_score, immediate_verdict = calculate_score(total_keyword_score, {})
    
    upsert_alert(call_sid, {
        "threat_score": immediate_score,
        "verdict": immediate_verdict
    })
    
    print(f"[SCAMSHIELD] INFO {call_sid} immediate score: {immediate_verdict} ({immediate_score})")
    
    # Check for immediate termination
    if immediate_score >= 70:
        print(f"[SCAMSHIELD] WARN Terminating high-risk call {call_sid}")
        r = VoiceResponse()
        r.say("This call has been flagged as high risk and will now be disconnected.", 
              voice="Polly.Joanna")
        r.hangup()
        return Response(str(r), mimetype="text/xml")
    
    # Continue to next question or end call
    if question_num < 4:
        r = VoiceResponse()
        gather = Gather(input="speech", action=f"{BASE_URL}/answer/{question_num+1}",
                      method="POST", speech_timeout="auto", language="en-IN")
        gather.say(f"Question {question_num+1}. {QUESTIONS[question_num]}", voice="Polly.Joanna")
        r.append(gather)
        return Response(str(r), mimetype="text/xml")
    else:
        # Final question answered - wait briefly for LLM then give final verdict
        time.sleep(2)  # Brief wait for LLM thread
        
        # Get final alert state
        final_alert = upsert_alert(call_sid, {})
        final_score = final_alert["threat_score"]
        final_verdict = final_alert["verdict"]
        
        print(f"[SCAMSHIELD] INFO Final verdict for {call_sid}: {final_verdict} ({final_score})")
        
        r = VoiceResponse()
        if final_verdict == "HIGH":
            r.say("This call has been flagged as high risk and will now be disconnected.", 
                  voice="Polly.Joanna")
        elif final_verdict == "MEDIUM":
            r.say("Thank you. Exercise caution with this call.", voice="Polly.Joanna")
        else:
            r.say("Thank you. Connecting you now.", voice="Polly.Joanna")
        r.hangup()
        return Response(str(r), mimetype="text/xml")

@app.route("/status", methods=["POST"])
def status():
    """Handle Twilio call status callbacks."""
    call_sid = request.form.get("CallSid", "unknown")
    call_status = request.form.get("CallStatus", "unknown")
    print(f"[SCAMSHIELD] INFO Call {call_sid} status: {call_status}")
    return "", 204

# ── 6. REST API ──────────────────────────────────────────────────────

def security_headers(response):
    """Add security headers to all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response

app.after_request(security_headers)

@app.route("/api/alerts")
def api_alerts():
    """Get all alerts, newest first."""
    with alerts_lock:
        return jsonify(list(alerts))

@app.route("/api/alerts/<call_sid>")
def api_alert(call_sid):
    """Get single alert by call SID."""
    with alerts_lock:
        for a in alerts:
            if a["call_sid"] == call_sid:
                return jsonify(a)
    return jsonify({"error": "not found"}), 404

@app.route("/api/metrics")
def api_metrics():
    """Get summary metrics."""
    with alerts_lock:
        total = len(alerts)
        high = sum(1 for a in alerts if a["verdict"] == "HIGH")
        med = sum(1 for a in alerts if a["verdict"] == "MEDIUM")
        low = sum(1 for a in alerts if a["verdict"] == "LOW")
        avg = round(sum(a["threat_score"] for a in alerts) / total, 1) if total else 0
    return jsonify({
        "total_calls": total,
        "high_risk": high,
        "medium_risk": med,
        "low_risk": low,
        "avg_score": avg
    })

@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "version": "1.0.0"})

# ── 7. DASHBOARD HTML (inline string) ────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScamShield - Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f9fafb; }
        
        .header { background: #111827; color: white; padding: 1rem 2rem; }
        .header h1 { font-size: 1.5rem; font-weight: 600; }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
        .metric-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .metric-card h3 { font-size: 0.875rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
        .metric-card p { font-size: 2rem; font-weight: 700; margin-top: 0.5rem; }
        
        .chart-section { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 2rem; }
        .chart-section h2 { margin-bottom: 1rem; color: #111827; }
        
        .alerts-section { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .alerts-header { padding: 1.5rem; border-bottom: 1px solid #e5e7eb; }
        .alerts-header h2 { color: #111827; }
        
        .alert-row { padding: 1rem 1.5rem; border-bottom: 1px solid #f3f4f6; cursor: pointer; transition: background 0.2s; }
        .alert-row:hover { background: #f9fafb; }
        .alert-row:last-child { border-bottom: none; }
        
        .alert-summary { display: flex; justify-content: between; align-items: center; }
        .alert-info { flex: 1; }
        .alert-caller { font-weight: 600; color: #111827; }
        .alert-time { font-size: 0.875rem; color: #6b7280; margin-top: 0.25rem; }
        
        .alert-badges { display: flex; gap: 0.5rem; align-items: center; }
        .verdict-badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .verdict-high { background: #fef2f2; color: #dc2626; }
        .verdict-medium { background: #fef3c7; color: #d97706; }
        .verdict-low { background: #f0fdf4; color: #16a34a; }
        
        .score-pill { background: #f3f4f6; color: #374151; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875rem; font-weight: 500; }
        
        .alert-details { display: none; padding: 1rem 0; border-top: 1px solid #f3f4f6; margin-top: 1rem; }
        .alert-details.expanded { display: block; }
        
        .transcripts { margin-bottom: 1rem; }
        .transcripts h4 { margin-bottom: 0.5rem; color: #374151; }
        .transcript { background: #f9fafb; padding: 0.75rem; border-radius: 4px; margin-bottom: 0.5rem; font-size: 0.875rem; }
        .transcript mark { background: #fef08a; padding: 0.125rem 0.25rem; border-radius: 2px; }
        
        .tactics { margin-bottom: 1rem; }
        .tactics h4 { margin-bottom: 0.5rem; color: #374151; }
        .tactic-chip { display: inline-block; background: #fee2e2; color: #dc2626; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-right: 0.5rem; margin-bottom: 0.25rem; }
        
        .reasoning { }
        .reasoning h4 { margin-bottom: 0.5rem; color: #374151; }
        .reasoning p { font-size: 0.875rem; color: #6b7280; font-style: italic; }
        
        @media (max-width: 640px) {
            .container { padding: 1rem; }
            .metrics { grid-template-columns: repeat(2, 1fr); }
            .header { padding: 1rem; }
            .alert-summary { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
            .alert-badges { margin-top: 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ScamShield — Live Dashboard</h1>
    </div>
    
    <div class="container">
        <div class="metrics" id="metrics">
            <div class="metric-card">
                <h3>Total Calls</h3>
                <p id="total-calls">0</p>
            </div>
            <div class="metric-card">
                <h3>High Risk</h3>
                <p id="high-risk">0</p>
            </div>
            <div class="metric-card">
                <h3>Medium Risk</h3>
                <p id="medium-risk">0</p>
            </div>
            <div class="metric-card">
                <h3>Avg Score</h3>
                <p id="avg-score">0</p>
            </div>
        </div>
        
        <div class="chart-section">
            <h2>Threat Score Trend</h2>
            <canvas id="score-chart" width="600" height="120"></canvas>
        </div>
        
        <div class="alerts-section">
            <div class="alerts-header">
                <h2>Recent Alerts</h2>
            </div>
            <div id="alerts-list">
                <!-- Alerts will be populated here -->
            </div>
        </div>
    </div>
    
    <script>
        let alerts = [];
        
        function formatTime(isoString) {
            return new Date(isoString).toLocaleString();
        }
        
        function highlightKeywords(text, keywords) {
            let result = text;
            keywords.forEach(keyword => {
                const regex = new RegExp(`(${keyword})`, 'gi');
                result = result.replace(regex, '<mark>$1</mark>');
            });
            return result;
        }
        
        function toggleAlertDetails(callSid) {
            const details = document.getElementById(`details-${callSid}`);
            if (details) {
                details.classList.toggle('expanded');
            }
        }
        
        function renderAlerts(alertsData) {
            const container = document.getElementById('alerts-list');
            if (alertsData.length === 0) {
                container.innerHTML = '<div style="padding: 2rem; text-align: center; color: #6b7280;">No alerts yet</div>';
                return;
            }
            
            container.innerHTML = alertsData.map(alert => {
                const verdictClass = `verdict-${alert.verdict.toLowerCase()}`;
                const transcriptsHtml = alert.transcripts.map(t => 
                    `<div class="transcript">${highlightKeywords(t, alert.keyword_hits)}</div>`
                ).join('');
                
                const tacticsHtml = (alert.llm_result.detected_tactics || []).map(tactic =>
                    `<span class="tactic-chip">${tactic}</span>`
                ).join('');
                
                return `
                    <div class="alert-row" onclick="toggleAlertDetails('${alert.call_sid}')">
                        <div class="alert-summary">
                            <div class="alert-info">
                                <div class="alert-caller">${alert.caller_number}</div>
                                <div class="alert-time">${formatTime(alert.timestamp)}</div>
                            </div>
                            <div class="alert-badges">
                                <span class="verdict-badge ${verdictClass}">${alert.verdict}</span>
                                <span class="score-pill">${alert.threat_score}</span>
                            </div>
                        </div>
                        <div class="alert-details" id="details-${alert.call_sid}">
                            <div class="transcripts">
                                <h4>Transcripts</h4>
                                ${transcriptsHtml || '<div class="transcript">No transcripts yet</div>'}
                            </div>
                            ${tacticsHtml ? `
                                <div class="tactics">
                                    <h4>Detected Tactics</h4>
                                    ${tacticsHtml}
                                </div>
                            ` : ''}
                            ${alert.llm_result.reasoning ? `
                                <div class="reasoning">
                                    <h4>AI Analysis</h4>
                                    <p>${alert.llm_result.reasoning}</p>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function drawChart(alertsData) {
            const canvas = document.getElementById('score-chart');
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;
            
            ctx.clearRect(0, 0, width, height);
            
            if (alertsData.length === 0) {
                ctx.fillStyle = '#6b7280';
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('No data to display', width / 2, height / 2);
                return;
            }
            
            const last10 = alertsData.slice(0, 10).reverse();
            const barWidth = width / Math.max(10, last10.length);
            const maxHeight = height - 30;
            
            // Draw HIGH threshold line (score 70)
            const thresholdY = height - (70 / 100 * maxHeight) - 20;
            ctx.strokeStyle = '#dc2626';
            ctx.setLineDash([5, 5]);
            ctx.beginPath();
            ctx.moveTo(0, thresholdY);
            ctx.lineTo(width, thresholdY);
            ctx.stroke();
            ctx.setLineDash([]);
            
            // Draw bars
            last10.forEach((alert, i) => {
                const score = alert.threat_score;
                const barHeight = (score / 100) * maxHeight;
                const x = i * barWidth + barWidth * 0.1;
                const y = height - barHeight - 20;
                const barActualWidth = barWidth * 0.8;
                
                // Color based on score
                if (score >= 70) {
                    ctx.fillStyle = '#dc2626';
                } else if (score >= 40) {
                    ctx.fillStyle = '#d97706';
                } else {
                    ctx.fillStyle = '#16a34a';
                }
                
                ctx.fillRect(x, y, barActualWidth, barHeight);
                
                // Score label
                ctx.fillStyle = '#374151';
                ctx.font = '12px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText(score.toString(), x + barActualWidth / 2, y - 5);
            });
        }
        
        async function fetchMetrics() {
            try {
                const response = await fetch('/api/metrics');
                const metrics = await response.json();
                
                document.getElementById('total-calls').textContent = metrics.total_calls;
                document.getElementById('high-risk').textContent = metrics.high_risk;
                document.getElementById('medium-risk').textContent = metrics.medium_risk;
                document.getElementById('avg-score').textContent = metrics.avg_score;
            } catch (error) {
                console.error('Failed to fetch metrics:', error);
            }
        }
        
        async function fetchAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alertsData = await response.json();
                
                alerts = alertsData;
                renderAlerts(alertsData);
                drawChart(alertsData);
            } catch (error) {
                console.error('Failed to fetch alerts:', error);
            }
        }
        
        // Initial load
        fetchMetrics();
        fetchAlerts();
        
        // Poll every 2 seconds
        setInterval(() => {
            fetchMetrics();
            fetchAlerts();
        }, 2000);
    </script>
</body>
</html>"""

@app.route("/")
def dashboard():
    """Serve the live dashboard."""
    return DASHBOARD_HTML

# ── 8. ENTRY POINT ───────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)