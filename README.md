# ScamShield AI — Multilingual Scam & Phishing Detector

> **"Think Before You Click."**  
> AI-Powered Multilingual Phishing and Scam Message Detector designed for Indian digital citizens.  
> Supporting **English**, **தமிழ் (Tamil)**, and **Tanglish**.

---

## 🛡️ Project Overview & Purpose

Digital financial fraud, Smishing (SMS phishing), and coercive social engineering scams have grown exponentially across India—particularly targeting non-English speaking citizens via WhatsApp, Telegram, and SMS. 

**ScamShield AI** is a client-side cybersecurity defense application that inspects incoming messages, hyperlinks, and transcribed phone call scripts to detect fraudulent patterns before users click deceptive links or surrender their financial credentials.

Developed specifically for a national-level technical hackathon, ScamShield AI operates **100% offline** directly inside standard modern web browsers with **zero build processes, zero framework dependencies, and zero backend server requirements**.

---

## 🚀 Key Features

1. **Cybersecurity Command Center Interface**:
   - Dark cyber navy aesthetics (`#060913`, `#0c142e`) with electric cyan (`#00f5ff`) and neon violet accents.
   - Smooth animated circular risk meters, status radar effects, and high-contrast risk badges.
   - Fully responsive for desktop, tablet, and mobile browsers with collapsible navigation.

2. **Multilingual Threat Detection Engine**:
   - Heuristic evaluation for messages written in **English**, **Tamil (Unicode தமிழ் script)**, and **Tanglish (phonetic Tamil in Latin characters)**.
   - Automatic language detection or manual language override.
   - One-click sample test presets for immediate evaluation.

3. **Safe Suspicious Phrase Highlighting**:
   - Visually highlights exact trigger phrases directly inside the submitted message.
   - Uses strict DOM node manipulation to avoid unescaped `innerHTML`, guaranteeing complete resistance to Cross-Site Scripting (XSS).
   - Generates breakdown cards detailing the specific threat vector and rationale for each detected phrase.

4. **URL Threat Inspector**:
   - Inspects web links for unencrypted HTTP transport, direct IP hosts, known URL shorteners, lookalike banking domains, suspicious top-level domains (`.xyz`, `.top`, `.tk`), and phishing lures in pathnames.
   - Parses URLs locally without pinging or executing external code.

5. **Voice Analysis & Call Extortion Detection**:
   - Uses the browser's native **Web Speech API** (`SpeechRecognition` / `webkitSpeechRecognition`) for live voice transcription in English (India) and Tamil.
   - Features an honest, graceful fallback with manual transcription input when speech recognition is unsupported or restricted by browser permissions.

6. **Actionable Safety Recommendations Checklist**:
   - Dynamically generated defense checklist customized to detected threat vectors.
   - One-click **Copy Safety Advice** button with clipboard integration and visual toast notifications.
   - Highlights the Indian National Cybercrime Helpline: **Dial 1930** and **cybercrime.gov.in**.

7. **Scam Awareness Learning Center & Interactive Quiz**:
   - 8 bilingual (English/Tamil) knowledge base guides detailing common scams (UPI QR traps, fake bank notices, digital arrests, etc.).
   - Interactive 5-question scenario quiz with real-time feedback, detailed explanations, session scoring, and progress tracking.

8. **Scam Trends & Telemetry Dashboard**:
   - Dynamic CSS-based charts displaying risk distribution, language breakdown, and top scam categories.
   - Computed directly from actual local browser scans, with a toggleable demonstration telemetry mode for evaluation.

9. **Privacy-Preserving Local Analysis History**:
   - Saved locally using browser `localStorage`.
   - Stores only sanitized message snippets (first 65 characters) and metadata—never storing sensitive passwords, OTPs, or full personal texts.
   - Searchable, filterable by risk level, individual record deletion, clear-all modal confirmation, and JSON audit log export.

---

## 🛠️ Technologies Used

- **HTML5**: Semantic document layout, SVG iconography, ARIA accessibility landmarks.
- **CSS3**: Custom CSS variables, responsive grid/flexbox layouts, CSS animations, glassmorphism, scanlines.
- **Vanilla JavaScript (ES6+)**: Modular object-oriented architecture, Regular Expression pattern dictionaries, DOM manipulation, Web Speech API, Clipboard API, and LocalStorage API.
- **Zero External Dependencies**: No npm, no Node.js, no Vite, no React, no CDNs required.

---

## 💻 How to Run the Application

The application is completely self-contained and requires no installation or local server.

### Steps:
1. Open your file manager and navigate to the project directory:
   ```
   ScamShield-AI-Simple
   ```
2. Double-click or open **`index.html`** directly in **Google Chrome** (or Microsoft Edge / Brave / Firefox).
3. The ScamShield AI Command Center will immediately load and is ready to use!

---

## 🔍 How the Rule-Based Detection Works

ScamShield AI utilizes a weighted heuristic scoring algorithm ($0 - 100$) based on known threat vectors:

1. **Pattern Matching across 10 Vector Classes**:
   - OTP credential solicitation (Weight: 35)
   - Account blocking & KYC suspension threats (Weight: 30)
   - High-pressure urgency tactics (Weight: 18)
   - Suspicious links, shorteners, & APK downloads (Weight: 22)
   - UPI PIN and QR receipt traps (Weight: 35)
   - Fake work-from-home job registration fees (Weight: 30)
   - Unsolicited lottery / prize claims (Weight: 32)
   - Postal parcel / courier extortion (Weight: 25)
   - High-return investment & crypto scams (Weight: 30)
   - Law enforcement impersonation & digital arrest threats (Weight: 35)

2. **Compound Vector Boosters**:
   - Attackers frequently combine multiple vectors (e.g., *Account Suspension Threat* + *Urgency* + *OTP Request*).
   - When compounding vectors appear together, the engine applies synergy multipliers, escalating the threat score to **High Risk (61–100)**.

3. **Risk Stratification**:
   - **0 – 30**: Low Risk (Safe / Clean heuristics)
   - **31 – 60**: Medium Risk (Exercise caution, potential warning signs)
   - **61 – 100**: High Risk (Critical threat, strong scam probability)

4. **Safe Language Parsing**:
   - Dictionaries are tailored with regular expressions for both native Tamil script (e.g., `வங்கி கணக்கு இன்று முடக்கப்படும்`) and phonetically romanized Tanglish (e.g., `account block aagapoguthu`, `otp kudu`, `link click panni`).

---

## ⚠️ Current Scope & Limitations

- **Rule-Based Engine**: This version uses regex heuristic rules and pattern matching rather than a deep learning neural model. It does not connect to live external threat-intelligence APIs.
- **No False Guarantees**: A score of 0 indicates that no known scam patterns were matched in the heuristic dictionary; it does not guarantee that an unknown or novel scam is completely safe.
- **URL Inspection**: URLs are inspected based on static lexical characteristics. ScamShield does not actively fetch or render external web pages to protect user privacy and safety.
- **Web Speech API**: Live audio speech recognition relies on the browser's built-in Web Speech API, which requires appropriate microphone permissions and internet connectivity in Google Chrome. For unsupported environments, manual transcript input is fully supported.

---

## 📞 Emergency Contacts (India)

If you or someone you know has fallen victim to cyber fraud:
- **National Cyber Crime Helpline**: Dial **1930**
- **National Cybercrime Reporting Portal**: [https://cybercrime.gov.in](https://cybercrime.gov.in)
