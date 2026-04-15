# ScamShield Layer 3

## What it does

ScamShield is a real-time vishing (voice phishing) detection system that intercepts phone calls via Twilio, uses AI to screen callers with security questions, and analyzes responses with Groq's Llama 3 LLM to detect scam indicators. All results are displayed on a live web dashboard with threat scoring and real-time alerts.

## Tech stack

| Component | Technology |
|-----------|------------|
| **Twilio** | Call handling, speech-to-text, TwiML responses |
| **Groq** | Llama 3 LLM for intent analysis and scam detection |
| **Render** | Cloud hosting platform (free tier deployment) |
| **Flask** | Python web framework for webhooks and API |
| **Dashboard** | Pure HTML/CSS/JS with Canvas 2D charts |

## Setup in 5 steps

1. **Clone repo and install dependencies**
   ```bash
   git clone <repo-url>
   cd scamshield-layer3
   pip install -r requirements.txt
   ```

2. **Copy `.env.example` to `.env` and fill in values**
   ```bash
   cp .env.example .env
   # Edit .env with your Twilio and Groq API credentials
   ```

3. **Deploy to Render — set env vars in dashboard**
   - Connect your GitHub repo to Render
   - Set all environment variables from `.env` in Render dashboard
   - Deploy as Web Service

4. **Set Twilio webhook URL to `https://your-app.onrender.com/voice`**
   - In Twilio Console, configure your phone number's webhook URL
   - Set HTTP method to POST

5. **Call your Twilio number to test**
   - The system will answer and ask screening questions
   - Check the dashboard for real-time threat analysis

## Dashboard URL

Access your live dashboard at: `https://your-app.onrender.com`

## How threat scoring works

The system calculates threat scores using this formula:
```
score = min(100, keyword_hits * 8 + llm_confidence * 40 + tactic_count * 5)
```

- **LOW** (0-39): Safe caller, call proceeds normally
- **MEDIUM** (40-69): Suspicious activity, user warned to exercise caution  
- **HIGH** (70-100): High-risk scam detected, call automatically terminated