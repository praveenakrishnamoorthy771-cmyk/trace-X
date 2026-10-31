# TRACE-X — Tactical Reconstruction and Cyber Evidence Explorer

TRACE-X is a browser-based cybersecurity investigation training platform. It helps learners practise reconstructing a simulated cyberattack from fictional security telemetry.

The application is built with **HTML, CSS, and vanilla JavaScript**. It runs directly in a modern web browser and does not require a server, database, account, or installation.

## Project Objectives

- Practise identifying relevant security events among benign log entries.
- Reconstruct an attack timeline in chronological order.
- Map observed activities to MITRE ATT&CK techniques.
- Connect events through cause-and-effect relationships.
- Generate a scored forensic report with an event-by-event audit.

## Features

- Six cybersecurity investigation categories.
- One playable scenario in each category.
- Randomised evidence cards, including benign decoy events.
- Selection of exactly eight relevant events per scenario.
- Timeline reconstruction using move-up and move-down controls.
- MITRE ATT&CK technique attribution.
- Cause-and-effect attack-chain builder.
- Automatic scoring out of 100.
- Forensic report with score breakdown, narrative reconstruction, and audit table.
- Retry and scenario-navigation options.
- Responsive dark, security-operations-style interface.

## Investigation Categories and Scenarios

| Category | Scenario |
|---|---|
| Phishing & Social Engineering | The Malicious Invoice |
| Malware & Initial Compromise | The Silent Payload |
| Credential Attacks | The Compromised Account |
| Lateral Movement | The Hidden Pivot |
| Data Collection & Exfiltration | The Missing Records |
| Insider Threat | The Midnight Access |

Each scenario contains eight relevant attack events and a number of benign decoy events. All organisations, users, hosts, and telemetry in the scenarios are fictional.

## Investigation Workflow

A learner completes the following six stages:

1. **Mission Brief** — Read the case details, target system, severity, incident time, and investigation objective.
2. **Evidence Board** — Review the shuffled telemetry cards and select exactly eight relevant events.
3. **Timeline Reconstruction** — Arrange the selected events in chronological order.
4. **MITRE ATT&CK Attribution** — Assign the appropriate ATT&CK technique to each event.
5. **Causal Mapping** — Connect events using cause-and-effect links to form the attack chain.
6. **Forensic Report** — Submit the investigation and review the score, narrative, and event audit table.

## Scoring System

The application awards a maximum of 100 points:

| Component | Maximum score | Scoring rule |
|---|---:|---|
| Evidence selection and timeline | 40 | Relevant-event selection and correct timeline positions; decoy selections are penalised. |
| MITRE ATT&CK mapping | 30 | Points are awarded for each event mapped to the correct technique. |
| Causal links | 30 | Correct links earn points and incorrect links lose points. |
| **Total** | **100** | Sum of the three components. |

### Performance Ratings

- **100:** Master Incident Responder
- **75–99:** Senior Security Analyst
- **Below 75:** Junior Triage Analyst

## Technology Stack

| Technology / Tool | Purpose |
|---|---|
| HTML5 | Application structure and screens |
| CSS3 | Styling, layout, and responsive interface |
| JavaScript (ES6) | Application logic, state, validation, and scoring |
| MITRE ATT&CK | Adversary tactic and technique reference framework |
| Google Fonts | Interface typography |
| Font Awesome 6.5.1 | Icons |
| Modern web browser | Running the application |
| Node.js, Playwright, Chromium, Python | Verification and testing described in the project report |

No JavaScript framework or backend is required by the application.

## Project Structure

The project consists of these files:

```text
TRACE-X/
├── index.html   # Main application page and interface structure
├── style.css    # Styles, theme, layouts, and responsive design
├── app.js       # Navigation, investigation workflow, validation, scoring, and reports
├── data.js      # Scenario data, telemetry events, ATT&CK options, and answer keys
└── README.md    # Project documentation
```

Keep the files in the same project folder because the HTML page loads the CSS and JavaScript files.

## How to Run the Project

1. Download or copy the TRACE-X project folder to your computer.
2. Make sure `index.html`, `style.css`, `app.js`, and `data.js` are in the same folder.
3. Open the project folder.
4. Double-click **`index.html`**.
5. The application opens in your default web browser.
6. Select an investigation category and scenario to begin.

You can also open `index.html` from a browser using **File → Open File**.

> The application does not need a local server or database. Google Fonts and Font Awesome are loaded from online CDNs in the delivered version, so an internet connection may be needed for those fonts and icons.

## How to Use

1. Open the application and select **Select Category & Start**.
2. Choose one of the six investigation categories.
3. Select the available scenario and read its mission brief.
4. On the evidence board, select exactly eight events.
5. Arrange the selected events in chronological order.
6. Choose a MITRE ATT&CK technique for each event.
7. Create the cause-and-effect links between the events.
8. Submit the investigation to view the forensic report.
9. Review the score breakdown and event-by-event audit.
10. Retry the scenario or return to the categories screen.

## Testing and Verification

The project report describes the following verification activities:

- A data-integrity audit checked scenario event identifiers, relevance flags, timeline order, ATT&CK answers, causal pairs, and category membership.
- A scoring test suite covered six learner-behaviour cases for each of the six scenarios, for a total of 36 test runs. The application scores matched an independent implementation of the scoring rules.
- A scripted end-to-end browser walkthrough completed the first scenario and produced a score of 100/100.

These are software verification results. They do not establish improved learning outcomes; a learner evaluation has not been conducted.

## Limitations

- The project uses authored, fictional scenarios rather than real incident logs.
- It does not connect to SIEM or EDR platforms.
- There is no server-side storage, user account system, or leaderboard.
- Investigation progress is held in memory and is lost when the page is reloaded.
- Answer keys are available in the client-side JavaScript, so the application is intended for training and demonstration, not secure graded assessment.
- The project has not been evaluated in a classroom or with SOC analysts.
- Offline use may require local copies of the external fonts and icon resources.

## Future Enhancements

- Add server-side scoring and secure storage of results.
- Expand the scenario library and support branching investigations.
- Add interactive drag-and-drop timelines and causal graphs.
- Introduce adaptive hints.
- Support sanitised real-world training datasets.
- Improve accessibility and mobile interaction.
- Add instructor tools and classroom evaluation.

## Privacy and Ethical Use

TRACE-X is a training prototype. It uses fictional organisations, hosts, users, and generated log descriptions. The application code does not collect, store, or transmit personal information. It contains no exploit code or functional attack payloads. The scenarios must not be represented as records of real incidents.

## Team TRACE-X

**KPR Institute of Engineering and Technology (Autonomous)**  
Department of Artificial Intelligence and Data Science

| Team member | Roll number |
|---|---|
| Praveena K | 25AD129 |
| Prathekshaa M | 25AD127 |
| Yohith R | 25AD188 |

**Project Supervisor:** Vishnupriya Mam  
**Project:** Mini Project Report — October 2026

---

*This README is prepared from the TRACE-X mini project report.*
