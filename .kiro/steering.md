# Kiro Steering — ScamShield Layer 3

## Project identity
This is a Python/Flask vishing detection system deployed on Render (free tier). It intercepts phone calls via Twilio, analyses speech with Groq's Llama 3 LLM, and shows results on a live dashboard.

## Hard constraints — never violate these

1. **Single Python file**: All application code lives in `scamshield.py`. Do not create separate modules, blueprints, or subdirectories for application code.
2. **No database**: Use the in-memory `alerts` list only. Do not add SQLite, Redis, or any database dependency unless explicitly asked.
3. **No external frontend frameworks**: The dashboard must be pure HTML/CSS/vanilla JS. No React, Vue, Alpine, Bootstrap, Tailwind CDN, or Chart.js.
4. **No compiled assets**: No webpack, no npm, no build step of any kind.
5. **No additional APIs beyond Groq**: Do not add OpenAI, Anthropic, ElevenLabs, or any other API. Twilio STT is built-in and free.
6. **Thread safety**: Every read or write to `alerts` must use `alerts_lock`.
7. **Twilio timeout budget**: All TwiML responses must be returned within 5 seconds. Run LLM calls in background threads.

## Code style

- Python 3.9+ syntax; use f-strings, type hints on function signatures
- Max line length 100 characters
- Use `snake_case` for variables and functions, `UPPER_SNAKE` for module-level constants
- Add a one-line docstring to every function
- Use `print()` for logging (Render captures stdout); format as `[SCAMSHIELD] {level} {message}`
- Do not use `logging` module (unnecessary complexity for this demo)

## Environment

- Runtime: Python 3.9 on Render free tier (512 MB RAM, shared CPU)
- Process manager: gunicorn with 2 workers
- Port: read from `PORT` env var, default 5000
- All secrets from environment variables — never hardcode or commit keys

## Deployment target

Render Web Service (free tier):
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn scamshield:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60`
- Health check path: `/health`
- Keep-warm: UptimeRobot pings `/health` every 10 minutes

## Testing notes

Kiro should generate test scenarios that can be exercised with `curl` commands (no pytest required). Each task's acceptance criteria maps to a specific curl command or Python one-liner.

## What this project is NOT

- Not a production security system — it's a hackathon demo
- Not storing audio recordings — only plain-text transcripts
- Not handling concurrent calls beyond Python's GIL + 2 gunicorn workers
- Not PCI/HIPAA compliant — in-memory only, no persistence
