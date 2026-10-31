# TRACE-X — Tactical Reconstruction & Cyber Evidence eXplorer

**TRACE-X** is an interactive, standalone cybersecurity investigation and threat timeline reconstruction platform designed for hackathons, SOC analyst training, and cyber incident simulation.

---

## 🚀 Application Flow

```
TRACE-X Landing Page
       ↓
Category Selection (6 Categories: 3 Playable, 3 Coming Soon)
       ↓
Scenario Selection (The Malicious Invoice, The Silent Payload, The Compromised Account)
       ↓
Mission Brief (Case Summary, Severity, Targets, Objectives)
       ↓
Evidence Board (11–12 Randomized Telemetry Log Cards)
       ↓
Identify Relevant Evidence (Filter out Decoys, Select 8 Relevant Attack Events)
       ↓
Reconstruct Timeline (Arrange 8 Events Chronologically)
       ↓
Map MITRE ATT&CK (Attribute Tactics & Techniques from Neutral Log Descriptions)
       ↓
Build Causal Attack Graph (Link Cause → Effect Event Pairs)
       ↓
Submit & View Forensic Report (Score out of 100 with Audit Breakdown)
```

---

## 🛡️ Playable Categories & Scenarios

### 1. Phishing & Social Engineering — [AVAILABLE]
- **Scenario:** The Malicious Invoice
- **Difficulty:** Intermediate (10–15 mins)
- **Log Events:** 11 Events (8 Relevant Attack Events, 3 Decoys)
- **Attack Chain:** Spearphishing email delivery → Document application script invocation → External HTTPS C2 beaconing → LSASS memory access → SMB/PsExec lateral movement to DC-01 → Finance share enumeration → Encrypted 7z archiving → Outbound HTTP POST exfiltration.

### 2. Malware & Initial Compromise — [AVAILABLE]
- **Scenario:** The Silent Payload
- **Difficulty:** Advanced (12–18 mins)
- **Log Events:** 12 Events (8 Relevant Attack Events, 4 Decoys)
- **Attack Chain:** Web browser zip download → Executable wrapper script extraction → Encoded PowerShell execution → Registry Run key persistence setup → High-privilege Scheduled Task creation → Ingress stager binary tool transfer → Persistent HTTPS C2 beaconing → EDR alert for process memory injection into explorer.exe.

### 3. Credential Attacks — [AVAILABLE]
- **Scenario:** The Compromised Account
- **Difficulty:** Advanced (12–18 mins)
- **Log Events:** 12 Events (8 Relevant Attack Events, 4 Decoys)
- **Attack Chain:** Multi-account password spraying → Valid cloud webmail login without MFA → Legacy RC4 Kerberoasting service ticket request → SAM registry hive dump on APP-SRV-02 → Local Admin group membership elevation on DC-01 → Volume shadow copy creation → NTDS.dit password hash extract via esentutl → Encrypted SSH exfiltration.

---

## 🔒 Disabled Categories — [COMING SOON]
- Malware & Initial Compromise
- Lateral Movement
- Insider Threat

---

## 📊 Robust 40 / 30 / 30 Scoring System

| Component | Points | Description |
| :--- | :---: | :--- |
| **Timeline & Selection** | **40 Pts** | Isolating the 8 true attack events (+2.5 pts each, -2.5 penalty for decoys) + arranging exact chronological order (+2.5 pts per correct rank). |
| **MITRE ATT&CK Attribution** | **30 Pts** | Inferring and mapping correct MITRE technique IDs from neutral telemetry descriptions (+3.75 pts per event). |
| **Causal Link Mapping** | **30 Pts** | Connecting the 7 cause-and-effect pairs across the attack chain (+4.28 pts per pair). |
| **Total Max Score** | **100 Pts** | **100 / 100** achieved when all steps are completed perfectly. |

---

## 📂 File Architecture

Built using a standalone client-only web stack without external databases or backends:

- `index.html` — Layout for Landing, Categories, Scenarios, Stepper Nav, Brief, Evidence Board, Timeline, MITRE, Causal, and Report screens.
- `data.js` — Data architecture holding categories, scenarios, 11-12 evidence events per scenario with neutral descriptions, decoys, MITRE options, and answer keys.
- `app.js` — Randomized event card shuffle, stage progression, state management, 40/30/30 scoring engine, and audit report breakdown.
- `style.css` — Custom dark cybersecurity theme system, glassmorphism cards, glowing badges, status indicators, and responsive grid layouts.
- `README.md` — Project documentation and application guide.

---

## 💻 How to Run & Test

1. Open `index.html` directly in any browser (Chrome, Edge, Firefox, Safari).
2. Test **Phishing & Social Engineering** → *The Malicious Invoice*.
3. Test **Malware & Initial Compromise** → *The Silent Payload*.
4. Test **Credential Attacks** → *The Compromised Account*.
5. Verify evidence card randomization, decoy penalties, MITRE attributions, and report output.
