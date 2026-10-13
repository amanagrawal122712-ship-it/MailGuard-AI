# MailGuard AI

MailGuard AI is a preliminary email phishing-risk analysis application.

## Architecture
- Frontend: React and Vite
- Backend: Node.js and Express
- AI service: Python and FastAPI
- Email integration: Gmail OAuth

## Features
- Gmail inbox connection
- Recent email listing
- Rule-based phishing-risk scoring
- Risk verdicts and detection reasons
- Dashboard for reviewing analysis results

## Local Development

### 1. Python AI service
Activate the virtual environment and install dependencies:

```bash
cd ai-service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Node.js backend
In a separate terminal:

```bash
cd server
npm install
npm start
```

Configure the required environment variables before starting the backend.

### 3. React frontend
In another terminal:

```bash
cd client
npm install
npm run dev
```

## Security Notes
- Never commit `.env` files, OAuth tokens, or pr- Never commit `.env` se- Never commicur- Never commit `.env` files, OAuth tokens, or pr- Never commit `.env`  and accessible onl- Never commit `.env` fil risk scores as preliminary indic- Never commit `.env` files,il is- Never commit `.env` files, s
Local developmeLocal developmeLocal de test cases have been exercised. Production security, deployment, and real-world detection accuracy still require verification.
