not completed fully

# SIH26106 — Email Threat Detection & Forensic Intelligence

##  What are we building?

An **AI-powered cybersecurity platform** that analyzes suspicious emails and finds:

* Phishing emails
* Suspicious/malicious URLs
* Suspicious IPs
* Risky attachments
* Domain information
* IP location & reputation
* Connected threat evidence

---

## 🛠️ Tech Stack

### Backend

* **Python**
* **FastAPI**
* Uvicorn

### AI / ML

* **Hugging Face Transformers**
* **PyTorch**
* Scikit-learn
* Pretrained phishing detection model

### Database

* **Supabase PostgreSQL**

### Frontend

* **React + TypeScript + Vite**
* Tailwind CSS

---

## 🤖 AI Model

### Email Phishing Detection

**Hugging Face:**
`specific-AI/email-agent-phishing-detection`

It analyzes:

```text
Sender + Subject + Email Body
        ↓
Phishing / Not Phishing
```

We are testing other pretrained models for **malicious URL detection**.

---

## 🔍 Forensics

The backend analyzes:

* Email headers
* SPF / DKIM / DMARC
* URLs
* Domains
* IP addresses
* Attachments
* Email body

---

## 🌐 APIs / Intelligence

### AbuseIPDB

Used for **IP reputation**.

Provides:

* Abuse confidence score
* Reports
* ISP
* Country
* Domain

### ipwho.is

Used for **IP geolocation**.

Provides:

* Country
* Region
* City
* Latitude / Longitude
* ISP / Organization

### RDAP

Used for **domain intelligence**.

Provides:

* Domain status
* Registration events
* Nameservers
* Domain information

---

## 🧠 Current Architecture

```text
Email (.eml)
     ↓
Email Forensics
     ↓
AI Phishing Detection
     ↓
URL / Domain Analysis
     ↓
IP Intelligence
     ↓
AbuseIPDB + Geolocation
     ↓
Attachment Analysis
     ↓
Threat Correlation
     ↓
Risk Engine
     ↓
Final Threat Result
```

---

## 📌 Current Status

✅ Email parser
✅ Email phishing AI model
✅ URL analysis
✅ Domain/RDAP intelligence
✅ IP analysis
✅ AbuseIPDB integration
✅ IP geolocation
✅ Attachment forensics
✅ Threat correlation
✅ Attack graph backend
✅ Supabase database

🔄 Risk Engine
🔄 Malicious URL ML model
🔄 BEC Detection
🔄 Anomaly Detection
🔄 Gemini AI Assistant
🔄 React Frontend

---

## 🔐 Important

API keys are stored locally in:

```text
backend/.env
```

`.env` is excluded from GitHub using `.gitignore`.

## ## 📊 Project Progress

### Overall Completion: ~48%

- **Completed:** ~48%
- **Remaining:** ~52%

