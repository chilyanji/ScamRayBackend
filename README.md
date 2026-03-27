🔐 ScamRay
Privacy-First Multi-Channel Phishing Detection System

🚀 An AI-powered mobile security solution that detects phishing across SMS, URLs, Emails, and OTP scams — in real-time, on-device, and privacy-first.

📱 App Overview

ScamRay is designed to combat modern phishing attacks that operate across multiple channels. Unlike traditional tools, it provides real-time, explainable, and privacy-preserving protection directly on your smartphone.

✨ Key Features
🔍 Multi-Channel Detection
SMS (Smishing)
Email phishing
Malicious URLs
OTP-based social engineering attacks
🤖 AI-Powered Detection Engine
On-device DistilBERT (TFLite) model
Rule-based heuristics engine
URL/domain reputation analysis
Hybrid decision system
⚡ Real-Time Protection
Detection latency: <120ms
Automatic SMS scanning
Instant alerts & blocking
🧠 Explainable AI (Aditya AI)
Provides clear reasons for every detection
Highlights suspicious patterns (urgency, fake domains, etc.)
Improves user awareness over time
🔒 Privacy-First Architecture
100% on-device processing
No raw message data sent to servers
Secure token storage (Keystore / Secure Enclave)
Differential privacy for community reporting
👴 Senior Citizen Mode
Simplified UI
Loud alerts
Emergency SOS system
Family notification feature
👶 Children Safety Module
Screen time control
Safe browsing protection
Suspicious SMS detection
Parental monitoring tools
⚠️ Automated Threat Handling
Block malicious links
Quarantine suspicious messages
Risk classification system:
Safe
Suspicious
Likely Phishing
High Risk
Critical
📊 Performance
Metric	Value
Precision	96.8%
Recall	95.3%
Detection Time	<120ms
🏗️ Architecture
Layer 5 → UI (Android App + Senior Mode)
Layer 4 → Explainability Engine (LIME)
Layer 3 → Decision Engine (Risk Scoring)
Layer 2 → Detection Modules (ML + Rules + URL)
Layer 1 → Channel Adapters (SMS, Email, Call)
Layer 0 → Privacy Layer (Tokenization + DP)
🧪 Tech Stack
📱 Mobile
Android (Java/Kotlin)
MVVM Architecture
🤖 AI / ML
DistilBERT (Quantized TFLite)
RoBERTa (Optional server-side)
LIME (Explainability)
🔐 Security
OAuth 2.0 (Email access)
Secure Enclave / Keystore
Differential Privacy
🌐 Backend (Optional)
FastAPI (Python)
REST APIs for deep analysis
📂 Project Structure
ScamRay/
│── app/
│   ├── ui/
│   ├── viewmodel/
│   ├── repository/
│   └── sms_receiver/
│
│── ml/
│   ├── distilbert.tflite
│   └── preprocessing/
│
│── backend/
│   ├── api/
│   └── models/
│
│── docs/
│── assets/
🚀 How It Works
Incoming SMS / URL / Email detected
Data processed locally (tokenization + masking)
ML + Rules + URL checks applied
Risk score generated
Explainable AI provides reason
Action taken (alert/block/quarantine)
🎯 Problem Solved
Traditional tools detect only one channel
Lack of explainability
Privacy risks (cloud-based scanning)
No mobile-first solution

👉 ScamRay solves all with a unified, on-device, explainable system

🌍 Impact
Protects users from phishing scams
Helps non-tech users & seniors
Builds cybersecurity awareness
Enables privacy-preserving AI
📸 Screenshots

(Add your app screenshots here)

👨‍💻 Team
Saurabh Kumar
Satyam Nayak
Shubham Singh

🎓 Computer Science & Engineering
📍 MMMUT Gorakhpur

📄 Documentation

Full project documentation available here:
👉 See attached PDF in repo

📌 Future Scope
Call (vishing) detection
WhatsApp & social media integration
Federated learning model updates
Global threat intelligence system
⭐ Support

If you like this project:

⭐ Star the repo
🍴 Fork it
🧠 Contribute

“Your phone is the most attacked device you own — ScamRay protects it.”
