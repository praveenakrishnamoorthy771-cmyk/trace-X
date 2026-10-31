/**
 * TRACE-X Data Store
 * Data architecture for 6 AVAILABLE categories, 6 playable investigation scenarios,
 * evidence logs with neutral descriptions, decoys, MITRE options, and answer keys.
 */

const TRACE_DATA = {
  categories: [
    {
      id: "phishing-social-engineering",
      name: "Phishing & Social Engineering",
      icon: "fa-envelope-open-text",
      description: "Investigate malicious emails, social engineering campaigns, malicious attachments, and user execution incidents.",
      status: "Available",
      availableScenariosCount: 1,
      scenarios: ["malicious-invoice"]
    },
    {
      id: "malware-initial-compromise",
      name: "Malware & Initial Compromise",
      icon: "fa-bug",
      description: "Investigate malware delivery, execution, persistence mechanisms, tool transfer, C2 communications, and EDR detection alerts.",
      status: "Available",
      availableScenariosCount: 1,
      scenarios: ["silent-payload"]
    },
    {
      id: "credential-attacks",
      name: "Credential Attacks",
      icon: "fa-key",
      description: "Investigate credential theft, password spraying, authentication abuse, account manipulation, and Active Directory database extraction.",
      status: "Available",
      availableScenariosCount: 1,
      scenarios: ["compromised-account"]
    },
    {
      id: "lateral-movement",
      name: "Lateral Movement",
      icon: "fa-network-wired",
      description: "Investigate internal network discovery, remote Desktop/SMB admin session creation, WinRM execution, PsExec driver installation, and domain pivots.",
      status: "Available",
      availableScenariosCount: 1,
      scenarios: ["hidden-pivot"]
    },
    {
      id: "data-collection-exfiltration",
      name: "Data Collection & Exfiltration",
      icon: "fa-file-export",
      description: "Investigate database queries, file discovery, multi-volume 7z archive creation, Base64 header encoding, HTTPS exfiltration, and log wipe scripts.",
      status: "Available",
      availableScenariosCount: 1,
      scenarios: ["missing-records"]
    },
    {
      id: "insider-threat",
      name: "Insider Threat",
      icon: "fa-user-secret",
      description: "Investigate off-hours workstation logins, confidential share access, file staging, encrypted ZIP creation, USB physical exfiltration, and file wiping.",
      status: "Available",
      availableScenariosCount: 1,
      scenarios: ["midnight-access"]
    }
  ],

  scenarios: {

    /* ==========================================================================
       SCENARIO 1: THE MALICIOUS INVOICE (Phishing & Social Engineering)
       ========================================================================== */
    "malicious-invoice": {
      id: "malicious-invoice",
      categoryId: "phishing-social-engineering",
      name: "The Malicious Invoice",
      description: "Investigate a suspicious phishing email that leads to endpoint compromise, credential access, lateral movement, sensitive data collection, archiving, and potential exfiltration.",
      difficulty: "Intermediate",
      estimatedTime: "10–15 minutes",
      status: "Available",
      brief: {
        caseId: "CASE-2026-INV88492",
        title: "Operation Dark Invoice",
        target: "Global Corp Financial Systems",
        incidentDate: "2026-07-24 09:14:02 UTC",
        severity: "HIGH / CRITICAL",
        summary: "At 09:14 UTC, Security Operations Center (SOC) sensors flagged anomalous network activity originating from workstation WS-FIN-04. Initial telemetry indicates suspicious external messaging followed by unusual child process invocation, outbound network connections, process memory access, remote session creation on DC-01, file staging, and high-volume data transmission.",
        objective: "Analyze log telemetry artifacts, separate genuine incident indicators from benign background noise, reconstruct the attack sequence chronologically, attribute MITRE ATT&CK techniques, connect causal pairs, and submit the final investigation report."
      },
      events: [
        {
          id: "EV-01",
          title: "Inbound Email Delivered with Attachment File",
          timestamp: "2026-07-24 09:14:02",
          source: "Email Security Gateway",
          host: "MAIL-GW-01",
          user: "sarah.jenkins",
          isRelevant: true,
          details: "External sender billing@vendor-update-net.com delivered email to sarah.jenkins@targetcorp.com with subject 'URGENT: Outstanding Invoice #INV-88492' and attached file Invoice_88492.docm (MD5: 4f8b9e11a22c33d). SPF soft-fail recorded.",
          correctStep: 1,
          mitreId: "T1566.001",
          mitreName: "Spearphishing Attachment"
        },
        {
          id: "EV-02",
          title: "Scheduled Backup Job Completed on Storage Host",
          timestamp: "2026-07-24 02:00:00",
          source: "Backup Agent - FS-01",
          host: "FS-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "Automated shadow copy volume backup on file server FS-01 completed successfully with 0 errors.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-03",
          title: "Document Application Executed Script Interpreter Process",
          timestamp: "2026-07-24 09:16:45",
          source: "EDR Agent - WS-FIN-04",
          host: "WS-FIN-04",
          user: "sarah.jenkins",
          isRelevant: true,
          details: "User sarah.jenkins opened Invoice_88492.docm. Process WINWORD.EXE spawned child process powershell.exe with encoded execution flags (-e aW52b2tl...).",
          correctStep: 2,
          mitreId: "T1204.002",
          mitreName: "User Execution: Malicious File"
        },
        {
          id: "EV-04",
          title: "Script Interpreter Established External HTTPS Connection",
          timestamp: "2026-07-24 09:17:10",
          source: "Perimeter Proxy Logs",
          host: "WS-FIN-04",
          user: "sarah.jenkins",
          isRelevant: true,
          details: "Process powershell.exe initiated encrypted outbound session to 194.26.29.112:443 and fetched secondary executable update_helper.exe into %TEMP%.",
          correctStep: 3,
          mitreId: "T1105",
          mitreName: "Ingress Tool Transfer"
        },
        {
          id: "EV-05",
          title: "Antivirus Definition Auto-Update Succeeded",
          timestamp: "2026-07-24 08:30:15",
          source: "Windows Defender Agent",
          host: "WS-FIN-04",
          user: "SYSTEM",
          isRelevant: false,
          details: "Security intelligence definition package v1.391.22.0 successfully downloaded and verified on workstation WS-FIN-04.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-06",
          title: "Unexpected Access Request to Authentication Service Memory",
          timestamp: "2026-07-24 09:22:30",
          source: "Sysmon Event ID 10 (ProcessAccess)",
          host: "WS-FIN-04",
          user: "sarah.jenkins",
          isRelevant: true,
          details: "Process update_helper.exe requested PROCESS_VM_READ access rights targeting lsass.exe. Plaintext NTLM credentials for domain service account 'admin_service' queried.",
          correctStep: 4,
          mitreId: "T1003.001",
          mitreName: "OS Credential Dumping: LSASS Memory"
        },
        {
          id: "EV-07",
          title: "Remote Authentication Session Established on Domain Server",
          timestamp: "2026-07-24 09:28:14",
          source: "Security Event Audit - DC-01",
          host: "DC-01",
          user: "admin_service",
          isRelevant: true,
          details: "Successful SMB remote authentication from host WS-FIN-04 (10.0.4.15) to DC-01 (10.0.1.5) using account 'admin_service'. Service PSEXESVC created remotely.",
          correctStep: 5,
          mitreId: "T1021.002",
          mitreName: "Remote Services: SMB/Windows Admin Shares"
        },
        {
          id: "EV-08",
          title: "IT Helpdesk Ticket Created for Hardware Peripheral",
          timestamp: "2026-07-24 09:30:00",
          source: "Internal Service Desk Portal",
          host: "SRV-DESK-01",
          user: "john.doe",
          isRelevant: false,
          details: "Employee john.doe submitted ticket #HD-9041 requesting paper jam resolution on 2nd floor network printer.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-09",
          title: "High-Volume Read Operations on Network Financial Share",
          timestamp: "2026-07-24 09:35:00",
          source: "File Audit Logs - FS-01",
          host: "FS-01",
          user: "admin_service",
          isRelevant: true,
          details: "Authenticated user 'admin_service' enumerated network share \\\\FS-01\\Finance_Archive and accessed 1,420 sensitive payroll and tax documents.",
          correctStep: 6,
          mitreId: "T1039",
          mitreName: "Data from Network Shared Drive"
        },
        {
          id: "EV-10",
          title: "Archiving Utility Invoked with Encrypted Parameter Flag",
          timestamp: "2026-07-24 09:41:20",
          source: "EDR Process Execution - DC-01",
          host: "DC-01",
          user: "admin_service",
          isRelevant: true,
          details: "Command line execution: 7z.exe a -hpPass2026! C:\\Windows\\Temp\\fin_archive.zip \\\\FS-01\\Finance_Archive\\*. Compressed 450 MB payload staged.",
          correctStep: 7,
          mitreId: "T1560.001",
          mitreName: "Archive via Utility with Encryption"
        },
        {
          id: "EV-11",
          title: "Unusually Large Outbound Transfer to External Endpoint",
          timestamp: "2026-07-24 09:48:05",
          source: "NetFlow Traffic Telemetry",
          host: "WS-FIN-04",
          user: "admin_service",
          isRelevant: true,
          details: "Host WS-FIN-04 transmitted 450 MB payload fin_archive.zip via HTTP POST multipart upload to external destination IP 185.220.101.5 (mega-sync-upload.com).",
          correctStep: 8,
          mitreId: "T1048.003",
          mitreName: "Exfiltration Over Web Service"
        }
      ],
      mitreOptions: [
        { id: "T1566.001", name: "T1566.001 — Initial Access: Spearphishing Attachment" },
        { id: "T1204.002", name: "T1204.002 — Execution: User Execution (Malicious File)" },
        { id: "T1105",     name: "T1105 — Command & Control: Ingress Tool Transfer" },
        { id: "T1003.001", name: "T1003.001 — Credential Access: OS Credential Dumping" },
        { id: "T1021.002", name: "T1021.002 — Lateral Movement: SMB/Windows Admin Shares" },
        { id: "T1039",     name: "T1039 — Collection: Data from Network Shared Drive" },
        { id: "T1560.001", name: "T1560.001 — Archive Data: Archive via Utility with Encryption" },
        { id: "T1048.003", name: "T1048.003 — Exfiltration: Exfiltration Over Web Service" },
        { id: "T1059.001", name: "T1059.001 — Execution: PowerShell Command Interpreter" },
        { id: "T1078.002", name: "T1078.002 — Persistence: Domain Accounts Hijacking" }
      ],
      answerKey: {
        relevantEventIds: ["EV-01", "EV-03", "EV-04", "EV-06", "EV-07", "EV-09", "EV-10", "EV-11"],
        timelineOrder: ["EV-01", "EV-03", "EV-04", "EV-06", "EV-07", "EV-09", "EV-10", "EV-11"],
        mitreMapping: {
          "EV-01": "T1566.001",
          "EV-03": "T1204.002",
          "EV-04": "T1105",
          "EV-06": "T1003.001",
          "EV-07": "T1021.002",
          "EV-09": "T1039",
          "EV-10": "T1560.001",
          "EV-11": "T1048.003"
        },
        causalPairs: [
          { cause: "EV-01", effect: "EV-03" },
          { cause: "EV-03", effect: "EV-04" },
          { cause: "EV-04", effect: "EV-06" },
          { cause: "EV-06", effect: "EV-07" },
          { cause: "EV-07", effect: "EV-09" },
          { cause: "EV-09", effect: "EV-10" },
          { cause: "EV-10", effect: "EV-11" }
        ],
        narrative: "An attacker delivered a spearphishing document to Sarah Jenkins. Opening the attachment executed embedded VBA code that launched PowerShell to download a C2 beacon payload (update_helper.exe). The payload extracted credentials from LSASS memory, allowing the attacker to pivot via SMB/PsExec to Domain Controller DC-01. The attacker then accessed the Finance network share, compressed and password-encrypted stolen files using 7-Zip, and exfiltrated the 450 MB archive over HTTP to an external server."
      }
    },


    /* ==========================================================================
       SCENARIO 2: THE SILENT PAYLOAD (Malware & Initial Compromise)
       ========================================================================== */
    "silent-payload": {
      id: "silent-payload",
      categoryId: "malware-initial-compromise",
      name: "The Silent Payload",
      description: "Investigate a suspected malware infection where a compressed file download leads to unexpected child process execution, registry run key persistence, scheduled task creation, tool transfer, C2 beaconing, and an EDR memory injection alert.",
      difficulty: "Advanced",
      estimatedTime: "12–18 minutes",
      status: "Available",
      brief: {
        caseId: "CASE-2026-PAYLOAD709",
        title: "Operation Silent Payload",
        target: "Engineering Workstation WS-ENG-08 & Enterprise Network",
        incidentDate: "2026-07-24 11:05:10 UTC",
        severity: "HIGH / CRITICAL",
        summary: "At 11:05 UTC, EDR sensors on workstation WS-ENG-08 flagged suspicious child process activity originating from a compressed archive download. Investigating analysts must trace initial delivery, script interpreter execution, persistence mechanism setup, tool transfer, C2 network communications, endpoint security alert triggers, and process memory injection.",
        objective: "Examine 12 log telemetry artifacts, separate genuine incident indicators from benign background noise, reconstruct the attack sequence chronologically, attribute MITRE ATT&CK techniques, connect causal pairs, and submit the final investigation report."
      },
      events: [
        {
          id: "EV-101",
          title: "Web Browser Download Logged for Compressed Archive File",
          timestamp: "2026-07-24 11:05:10",
          source: "Web Browser Telemetry (msedge.exe)",
          host: "WS-ENG-08",
          user: "alex.chen",
          isRelevant: true,
          details: "User alex.chen initiated download of Software_Update_v2.4.zip (MD5: e9a82b341f11c) from external site update-repo-cdn.org. File saved into C:\\Users\\alex.chen\\Downloads.",
          correctStep: 1,
          mitreId: "T1204.002",
          mitreName: "User Execution: Malicious File"
        },
        {
          id: "EV-102",
          title: "Automated Chrome Browser Component Update Succeeded",
          timestamp: "2026-07-24 10:30:00",
          source: "Google Update Service",
          host: "WS-ENG-08",
          user: "SYSTEM",
          isRelevant: false,
          details: "Background updater verified component hashes and updated widevine DRM plugin to v4.10.2557.0 with 0 errors.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-103",
          title: "Archive Extraction Executed Containing Executable Wrapper Script",
          timestamp: "2026-07-24 11:07:32",
          source: "File System Audit Logs",
          host: "WS-ENG-08",
          user: "alex.chen",
          isRelevant: true,
          details: "Extracted Software_Update_v2.4.zip revealing Software_Update.pdf.exe and embedded VBS script helper.vbs into %TEMP%\\Update_Stage\\.",
          correctStep: 2,
          mitreId: "T1204",
          mitreName: "User Execution"
        },
        {
          id: "EV-104",
          title: "Process Telemetry Recorded Script Interpreter Launched with Encoded Parameters",
          timestamp: "2026-07-24 11:08:15",
          source: "EDR Agent - Sysmon Event ID 1",
          host: "WS-ENG-08",
          user: "alex.chen",
          isRelevant: true,
          details: "Process wscript.exe spawned powershell.exe with flags '-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand aW52b2tl...'.",
          correctStep: 3,
          mitreId: "T1059.001",
          mitreName: "Command and Scripting Interpreter: PowerShell"
        },
        {
          id: "EV-105",
          title: "Windows Defender Real-Time Signature Sync Succeeded",
          timestamp: "2026-07-24 10:45:12",
          source: "Windows Defender Service",
          host: "WS-ENG-08",
          user: "SYSTEM",
          isRelevant: false,
          details: "Antivirus definition update package v1.391.1042.0 downloaded and applied successfully.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-106",
          title: "Persistence Mechanism Registered via Windows Registry Run Key",
          timestamp: "2026-07-24 11:12:40",
          source: "Sysmon Event ID 13 (RegistryValueSet)",
          host: "WS-ENG-08",
          user: "alex.chen",
          isRelevant: true,
          details: "Process powershell.exe added value 'SystemUpdateCheck' under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run pointing to C:\\Users\\Public\\svchost_update.exe.",
          correctStep: 4,
          mitreId: "T1547.001",
          mitreName: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
        },
        {
          id: "EV-107",
          title: "Scheduled Task Created for Automated Background Payload Execution",
          timestamp: "2026-07-24 11:15:05",
          source: "Security Audit Event ID 4698",
          host: "WS-ENG-08",
          user: "SYSTEM",
          isRelevant: true,
          details: "Task Scheduler created new task 'WinSecurityAudit' configured to run C:\\Users\\Public\\svchost_update.exe every 60 minutes with HIGHEST privileges.",
          correctStep: 5,
          mitreId: "T1053.005",
          mitreName: "Scheduled Task/Job: Scheduled Task"
        },
        {
          id: "EV-108",
          title: "Routine IT Remote Management Agent Heartbeat Logged",
          timestamp: "2026-07-24 11:20:00",
          source: "SCCM Client Service",
          host: "WS-ENG-08",
          user: "SYSTEM",
          isRelevant: false,
          details: "System Management Agent sent routine status heartbeat to deployment server SCCM-PRI-01.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-109",
          title: "Ingress Payload Binary Downloaded from Remote Infrastructure IP",
          timestamp: "2026-07-24 11:22:18",
          source: "Perimeter Firewall Log",
          host: "WS-ENG-08",
          user: "alex.chen",
          isRelevant: true,
          details: "Process svchost_update.exe initiated HTTP GET request to 198.51.100.201:8080/bin/stager.bin, saving 12 MB binary payload to %LOCALAPPDATA%\\Temp.",
          correctStep: 6,
          mitreId: "T1105",
          mitreName: "Ingress Tool Transfer"
        },
        {
          id: "EV-110",
          title: "Outbound Beaconing Session Established over Web Protocol",
          timestamp: "2026-07-24 11:28:45",
          source: "NetFlow Telemetry",
          host: "WS-ENG-08",
          user: "alex.chen",
          isRelevant: true,
          details: "Process svchost_update.exe established recurring encrypted HTTPS C2 communication to external domain c2-relay-node.net (198.51.100.201) at 45-second intervals.",
          correctStep: 7,
          mitreId: "T1071.001",
          mitreName: "Command and Control: Web Protocols"
        },
        {
          id: "EV-111",
          title: "Employee Ticket Created for Monitor Display Resolution Issue",
          timestamp: "2026-07-24 11:30:00",
          source: "IT Helpdesk Portal",
          host: "SRV-DESK-01",
          user: "alex.chen",
          isRelevant: false,
          details: "User logged ticket #HD-10492 reporting dual-monitor scaling display anomaly following graphics driver update.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-112",
          title: "Endpoint Security Sensor Flagged Memory Injection & C2 Telemetry Alert",
          timestamp: "2026-07-24 11:34:50",
          source: "EDR High-Severity Detection Alert",
          host: "WS-ENG-08",
          user: "SYSTEM",
          isRelevant: true,
          details: "EDR agent generated Alert #ALT-8841: Process svchost_update.exe detected performing reflective DLL injection into explorer.exe while maintaining active C2 channel to 198.51.100.201.",
          correctStep: 8,
          mitreId: "T1055",
          mitreName: "Process Injection"
        }
      ],
      mitreOptions: [
        { id: "T1204.002", name: "T1204.002 — Execution: User Execution (Malicious File)" },
        { id: "T1204",     name: "T1204 — Execution: User Execution" },
        { id: "T1059.001", name: "T1059.001 — Execution: PowerShell Command Interpreter" },
        { id: "T1547.001", name: "T1547.001 — Persistence: Registry Run Keys / Startup Folder" },
        { id: "T1053.005", name: "T1053.005 — Persistence: Scheduled Task" },
        { id: "T1105",     name: "T1105 — Command & Control: Ingress Tool Transfer" },
        { id: "T1071.001", name: "T1071.001 — Command & Control: Web Protocols (HTTPS)" },
        { id: "T1055",     name: "T1055 — Defense Evasion / Execution: Process Injection" },
        { id: "T1059.003", name: "T1059.003 — Execution: Windows Command Shell (Distractor)" },
        { id: "T1543.003", name: "T1543.003 — Persistence: Windows Service Creation (Distractor)" }
      ],
      answerKey: {
        relevantEventIds: ["EV-101", "EV-103", "EV-104", "EV-106", "EV-107", "EV-109", "EV-110", "EV-112"],
        timelineOrder: ["EV-101", "EV-103", "EV-104", "EV-106", "EV-107", "EV-109", "EV-110", "EV-112"],
        mitreMapping: {
          "EV-101": "T1204.002",
          "EV-103": "T1204",
          "EV-104": "T1059.001",
          "EV-106": "T1547.001",
          "EV-107": "T1053.005",
          "EV-109": "T1105",
          "EV-110": "T1071.001",
          "EV-112": "T1055"
        },
        causalPairs: [
          { cause: "EV-101", effect: "EV-103" },
          { cause: "EV-103", effect: "EV-104" },
          { cause: "EV-104", effect: "EV-106" },
          { cause: "EV-106", effect: "EV-107" },
          { cause: "EV-107", effect: "EV-109" },
          { cause: "EV-109", effect: "EV-110" },
          { cause: "EV-110", effect: "EV-112" }
        ],
        narrative: "User Alex Chen downloaded a compressed zip archive containing an executable wrapper. Extracting and launching the file executed an encoded PowerShell script that added a Registry Run key and created a high-privilege Scheduled Task for persistence. The persistent binary (svchost_update.exe) downloaded a secondary stager payload from C2 infrastructure (198.51.100.201), established encrypted HTTPS beaconing, and performed reflective DLL memory injection into explorer.exe, triggering a high-severity EDR alert."
      }
    },


    /* ==========================================================================
       SCENARIO 3: THE COMPROMISED ACCOUNT (Credential Attacks)
       ========================================================================== */
    "compromised-account": {
      id: "compromised-account",
      categoryId: "credential-attacks",
      name: "The Compromised Account",
      description: "Investigate a suspected account compromise involving password spraying, valid webmail authentication without MFA, Kerberoasting service ticket requests, SAM registry dumping, privilege group manipulation, shadow copy database access, and encrypted exfiltration.",
      difficulty: "Advanced",
      estimatedTime: "12–18 minutes",
      status: "Available",
      brief: {
        caseId: "CASE-2026-CRED9914",
        title: "Operation Broken Vault",
        target: "Identity & Active Directory Services",
        incidentDate: "2026-07-24 01:15:20 UTC",
        severity: "HIGH / CRITICAL",
        summary: "At 01:15 UTC, Identity Access Management (IAM) systems recorded high-frequency login failures targeting multiple corporate accounts. Short time later, a valid session was established without MFA, followed by unusual ticket requests, SAM registry queries, privilege group modifications, shadow copy creation on DC-01, and large encrypted database transfers.",
        objective: "Analyze 12 log telemetry artifacts, identify the 8 true attack events, reject 4 benign decoys, order the attack timeline chronologically, infer the correct MITRE ATT&CK techniques, link cause-and-effect pairs, and generate the final forensic analysis."
      },
      events: [
        {
          id: "EV-201",
          title: "Authentication Logs Recorded Repeated Failed Login Attempts Across Multiple Accounts",
          timestamp: "2026-07-24 01:15:20",
          source: "IAM Gateway Audit Logs",
          host: "IAM-GW-01",
          user: "MULTIPLE",
          isRelevant: true,
          details: "Single origin IP 185.220.101.44 generated 450 failed authentication attempts using a dictionary of common passwords across 45 distinct corporate identities within 3 minutes.",
          correctStep: 1,
          mitreId: "T1110.003",
          mitreName: "Brute Force: Password Spraying"
        },
        {
          id: "EV-202",
          title: "VPN Gateway Keep-Alive Health Probe Completed",
          timestamp: "2026-07-24 01:20:00",
          source: "VPN Concentrator Logs",
          host: "VPN-GW-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "Automated system probe verified tunnel status and IPsec gateway responsiveness with 0 drop packets.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-203",
          title: "Successful Interactive Authentication Logged from Unregistered External Address",
          timestamp: "2026-07-24 01:22:10",
          source: "Webmail Access Logs",
          host: "OWA-SRV-01",
          user: "m_rodriguez",
          isRelevant: true,
          details: "Account m_rodriguez@targetcorp.com authenticated successfully from external IP 185.220.101.44 via OWA interface without triggering MFA challenge.",
          correctStep: 2,
          mitreId: "T1078.004",
          mitreName: "Valid Accounts: Cloud Accounts"
        },
        {
          id: "EV-204",
          title: "Active Directory Ticket Request Transmitted Using Legacy Encryption Cipher",
          timestamp: "2026-07-24 01:28:45",
          source: "Kerberos KDC Event ID 4769",
          host: "DC-01",
          user: "m_rodriguez",
          isRelevant: true,
          details: "User account m_rodriguez requested Kerberos TGS ticket for Service Principal Name MSSQLSvc/db-prod.targetcorp.local:1433 explicitly specifying weak RC4_HMAC encryption.",
          correctStep: 3,
          mitreId: "T1558.003",
          mitreName: "Steal or Forge Kerberos Tickets: Kerberoasting"
        },
        {
          id: "EV-205",
          title: "Active Directory Domain Controller Directory Sync Completed",
          timestamp: "2026-07-24 01:30:00",
          source: "Active Directory Replication Agent",
          host: "DC-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "Routine scheduled directory partition replication between domain controllers DC-01 and DC-02 completed successfully.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-206",
          title: "Remote Registry Invocation & Security Hives Exported to Disk",
          timestamp: "2026-07-24 01:35:12",
          source: "EDR Command Audit",
          host: "APP-SRV-02",
          user: "m_rodriguez",
          isRelevant: true,
          details: "Remote execution of reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.hive and HKLM\\SYSTEM C:\\Windows\\Temp\\sys.hive on application server APP-SRV-02.",
          correctStep: 4,
          mitreId: "T1003.002",
          mitreName: "OS Credential Dumping: Security Account Manager"
        },
        {
          id: "EV-207",
          title: "Administrative Privileges Granted to Secondary Account",
          timestamp: "2026-07-24 01:42:00",
          source: "Security Audit Event ID 4728",
          host: "DC-01",
          user: "m_rodriguez",
          isRelevant: true,
          details: "Account m_rodriguez added compromised application service account 'svc_app_deploy' to the local Administrators group on Domain Controller DC-01.",
          correctStep: 5,
          mitreId: "T1098",
          mitreName: "Account Manipulation"
        },
        {
          id: "EV-208",
          title: "Automated Password Expiry Reminders Dispatched by HR System",
          timestamp: "2026-07-24 01:45:00",
          source: "HR Notification Portal",
          host: "HR-APP-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "Automated system dispatched 14-day password rotation reminder emails to 22 corporate accounts.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-209",
          title: "Volume Shadow Copy Snapshot Created on Infrastructure Host",
          timestamp: "2026-07-24 01:50:30",
          source: "VSS Service Logs",
          host: "DC-01",
          user: "SYSTEM",
          isRelevant: true,
          details: "Executed vssadmin create shadow /for=C: on Domain Controller DC-01. Snapshot created to bypass file lock on active system directory database.",
          correctStep: 6,
          mitreId: "T1003.003",
          mitreName: "OS Credential Dumping: NTDS"
        },
        {
          id: "EV-210",
          title: "Utility File Copy Performed on Locked Active Directory Database",
          timestamp: "2026-07-24 01:58:10",
          source: "Process Creation Logs",
          host: "DC-01",
          user: "svc_app_deploy",
          isRelevant: true,
          details: "Command line execution esentutl.exe /y /v \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\ntds.bak extracted domain password database.",
          correctStep: 7,
          mitreId: "T1003",
          mitreName: "OS Credential Dumping"
        },
        {
          id: "EV-211",
          title: "Automated WSUS Server Security Sync Succeeded",
          timestamp: "2026-07-24 02:02:10",
          source: "Windows Server Update Services",
          host: "WSUS-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "WSUS catalog sync verified signature integrity for 18 security patches with 0 errors.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-212",
          title: "Encrypted File Transfer Transmitted to External IP Address",
          timestamp: "2026-07-24 02:06:40",
          source: "Perimeter Firewall NetFlow",
          host: "DC-01",
          user: "svc_app_deploy",
          isRelevant: true,
          details: "Outbound SSH/SFTP session established from DC-01 (10.0.1.5) to external host 185.220.101.44 transferring 2.1 GB archive ntds_export.tar.gz.",
          correctStep: 8,
          mitreId: "T1048.002",
          mitreName: "Exfiltration Over Asymmetric Encrypted Protocol"
        }
      ],
      mitreOptions: [
        { id: "T1110.003", name: "T1110.003 — Credential Access: Password Spraying" },
        { id: "T1078.004", name: "T1078.004 — Defense Evasion: Valid Accounts (Cloud Accounts)" },
        { id: "T1558.003", name: "T1558.003 — Credential Access: Kerberoasting" },
        { id: "T1003.002", name: "T1003.002 — Credential Access: Security Account Manager (SAM)" },
        { id: "T1098",     name: "T1098 — Persistence: Account Manipulation" },
        { id: "T1003.003", name: "T1003.003 — Credential Access: NTDS Database Shadow Copy" },
        { id: "T1003",     name: "T1003 — Credential Access: OS Credential Dumping" },
        { id: "T1048.002", name: "T1048.002 — Exfiltration: Exfiltration Over Encrypted Non-C2 Protocol" },
        { id: "T1059.003", name: "T1059.003 — Execution: Windows Command Shell (Distractor)" },
        { id: "T1136.002", name: "T1136.002 — Persistence: Domain Account Creation (Distractor)" }
      ],
      answerKey: {
        relevantEventIds: ["EV-201", "EV-203", "EV-204", "EV-206", "EV-207", "EV-209", "EV-210", "EV-212"],
        timelineOrder: ["EV-201", "EV-203", "EV-204", "EV-206", "EV-207", "EV-209", "EV-210", "EV-212"],
        mitreMapping: {
          "EV-201": "T1110.003",
          "EV-203": "T1078.004",
          "EV-204": "T1558.003",
          "EV-206": "T1003.002",
          "EV-207": "T1098",
          "EV-209": "T1003.003",
          "EV-210": "T1003",
          "EV-212": "T1048.002"
        },
        causalPairs: [
          { cause: "EV-201", effect: "EV-203" },
          { cause: "EV-203", effect: "EV-204" },
          { cause: "EV-204", effect: "EV-206" },
          { cause: "EV-206", effect: "EV-207" },
          { cause: "EV-207", effect: "EV-209" },
          { cause: "EV-209", effect: "EV-210" },
          { cause: "EV-210", effect: "EV-212" }
        ],
        narrative: "An attacker executed a password spraying attack against enterprise accounts, successfully compromising m_rodriguez. Using valid webmail access, the attacker performed Kerberoasting to harvest service tickets, exported SAM hives from APP-SRV-02, and granted local Administrator rights to a secondary service account on DC-01. The attacker then created a volume shadow copy on DC-01, extracted active NTDS.dit domain password hashes via esentutl, and exfiltrated the 2.1 GB database archive over encrypted SFTP to external IP 185.220.101.44."
      }
    },


    /* ==========================================================================
       SCENARIO 4: THE HIDDEN PIVOT (Lateral Movement) - NEW
       ========================================================================== */
    "hidden-pivot": {
      id: "hidden-pivot",
      categoryId: "lateral-movement",
      name: "The Hidden Pivot",
      description: "Investigate internal network service discovery, interactive RDP pivoting, WinRM remote command execution, SMB hidden share access (C$), PsExec service driver installation, named pipe IPC control, and domain controller session hijacking.",
      difficulty: "Advanced",
      estimatedTime: "12–18 minutes",
      status: "Available",
      brief: {
        caseId: "CASE-2026-PIVOT304",
        title: "Operation Hidden Pivot",
        target: "Internal Workstation Subnet & Domain Controllers",
        incidentDate: "2026-07-24 16:10:00 UTC",
        severity: "HIGH / CRITICAL",
        summary: "At 16:10 UTC, network monitoring sensors detected unauthorized internal port scanning originating from workstation WS-DEV-04. The adversary enumerated active SMB and RDP services across the 10.0.4.0/24 subnet, leveraged harvested domain admin credentials, initiated WinRM remote management sessions, installed PsExec services on secondary server DB-SRV-02, and staged lateral access across domain infrastructure.",
        objective: "Examine 12 log telemetry artifacts, identify the 8 true attack events, reject 4 benign decoys, order the attack timeline chronologically, infer the correct MITRE ATT&CK techniques, link cause-and-effect pairs, and generate the final forensic analysis."
      },
      events: [
        {
          id: "EV-401",
          title: "Command Shell Network Service Discovery Operations Logged",
          timestamp: "2026-07-24 16:10:00",
          source: "Sysmon Event ID 1",
          host: "WS-DEV-04",
          user: "d_miller",
          isRelevant: true,
          details: "Process cmd.exe executed ping sweep script for i in {1..254}; do ping -n 1 10.0.4.$i; done and port scan targeting ports 135, 445, and 3389 across subnet.",
          correctStep: 1,
          mitreId: "T1046",
          mitreName: "Network Service Scanning"
        },
        {
          id: "EV-402",
          title: "Automated Network Adapter Speed Test Logged",
          timestamp: "2026-07-24 16:12:00",
          source: "Network Monitoring Agent",
          host: "WS-DEV-04",
          user: "SYSTEM",
          isRelevant: false,
          details: "Local network interface card performed routine throughput diagnostic test with gateway 10.0.4.1.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-403",
          title: "Active Directory Domain Trust and System Discovery Commands Executed",
          timestamp: "2026-07-24 16:15:20",
          source: "EDR Agent - WS-DEV-04",
          host: "WS-DEV-04",
          user: "d_miller",
          isRelevant: true,
          details: "Executed net group 'Domain Admins' /domain and nltest /dclist:targetcorp.local to identify active Domain Controllers.",
          correctStep: 2,
          mitreId: "T1069.002",
          mitreName: "Permission Groups Discovery: Domain Groups"
        },
        {
          id: "EV-404",
          title: "Remote Desktop Protocol Authentication Session Established to Secondary Workstation",
          timestamp: "2026-07-24 16:22:45",
          source: "Security Audit Event ID 4624 (Logon Type 10)",
          host: "WS-OPS-12",
          user: "d_miller",
          isRelevant: true,
          details: "Successful interactive RDP logon to host WS-OPS-12 (10.0.4.88) originating from WS-DEV-04 (10.0.4.15) using account d_miller.",
          correctStep: 3,
          mitreId: "T1021.001",
          mitreName: "Remote Services: Remote Desktop Protocol"
        },
        {
          id: "EV-405",
          title: "Scheduled Antivirus Full Disk Scan Initiated",
          timestamp: "2026-07-24 16:25:00",
          source: "Windows Defender Service",
          host: "WS-OPS-12",
          user: "SYSTEM",
          isRelevant: false,
          details: "Weekly scheduled malware signature scan initiated on system drive C: with normal CPU priority.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-406",
          title: "Process Telemetry Recorded Remote Management Command Execution",
          timestamp: "2026-07-24 16:30:10",
          source: "PowerShell Operational Log Event ID 4104",
          host: "WS-OPS-12",
          user: "d_miller",
          isRelevant: true,
          details: "Executed Invoke-Command -ComputerName DB-SRV-02 -ScriptBlock { Get-Process } via Windows Remote Management (WinRM / WS-Man) port 5985.",
          correctStep: 4,
          mitreId: "T1021.006",
          mitreName: "Remote Services: Windows Remote Management"
        },
        {
          id: "EV-407",
          title: "Remote Administrative Share Access Logged over SMB Protocol",
          timestamp: "2026-07-24 16:38:00",
          source: "Security Audit Event ID 5140",
          host: "DB-SRV-02",
          user: "d_miller",
          isRelevant: true,
          details: "Account d_miller accessed administrative hidden share \\\\DB-SRV-02\\C$ and IPC$ from source IP 10.0.4.88.",
          correctStep: 5,
          mitreId: "T1021.002",
          mitreName: "Remote Services: SMB/Windows Admin Shares"
        },
        {
          id: "EV-408",
          title: "Print Spooler Service Status Checked",
          timestamp: "2026-07-24 16:40:00",
          source: "Service Control Manager",
          host: "DB-SRV-02",
          user: "SYSTEM",
          isRelevant: false,
          details: "Spooler service verified status RUNNING following background spooler maintenance routine.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-409",
          title: "Service Control Manager Created New Remote Execution Driver Service",
          timestamp: "2026-07-24 16:45:15",
          source: "System Event ID 7045",
          host: "DB-SRV-02",
          user: "SYSTEM",
          isRelevant: true,
          details: "Service PSEXESVC created with image path %SystemRoot%\\PSEXESVC.exe remotely registered by host 10.0.4.88.",
          correctStep: 6,
          mitreId: "T1543.003",
          mitreName: "Create or Modify System Process: Windows Service"
        },
        {
          id: "EV-410",
          title: "Inter-Process Communication Named Pipe Connection Created",
          timestamp: "2026-07-24 16:51:30",
          source: "Sysmon Event ID 17 (PipeCreated)",
          host: "DB-SRV-02",
          user: "d_miller",
          isRelevant: true,
          details: "Process PSEXESVC.exe created named pipe \\\\.\\pipe\\psexecsvc-DB-SRV-02-stdin to handle interactive command execution.",
          correctStep: 7,
          mitreId: "T1055",
          mitreName: "Execution / IPC: Inter-Process Communication"
        },
        {
          id: "EV-411",
          title: "Database Nightly Transaction Log Rotation Completed",
          timestamp: "2026-07-24 16:55:00",
          source: "SQL Maintenance Job",
          host: "DB-SRV-02",
          user: "SYSTEM",
          isRelevant: false,
          details: "Automated transaction log truncation and archive backup completed with 0 errors.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-412",
          title: "High-Privilege Domain Controller Administrative Access Logged",
          timestamp: "2026-07-24 17:02:40",
          source: "Security Audit Event ID 4624",
          host: "DC-01",
          user: "d_miller",
          isRelevant: true,
          details: "Kerberos ticket request and remote command session established from DB-SRV-02 (10.0.2.15) to Domain Controller DC-01 (10.0.1.5) using d_miller credentials.",
          correctStep: 8,
          mitreId: "T1078.002",
          mitreName: "Valid Accounts: Domain Accounts"
        }
      ],
      mitreOptions: [
        { id: "T1046",     name: "T1046 — Discovery: Network Service Scanning" },
        { id: "T1069.002", name: "T1069.002 — Discovery: Domain Groups Discovery" },
        { id: "T1021.001", name: "T1021.001 — Lateral Movement: Remote Desktop Protocol" },
        { id: "T1021.006", name: "T1021.006 — Lateral Movement: Windows Remote Management (WinRM)" },
        { id: "T1021.002", name: "T1021.002 — Lateral Movement: SMB/Windows Admin Shares" },
        { id: "T1543.003", name: "T1543.003 — Persistence: Windows Service Creation" },
        { id: "T1055",     name: "T1055 — Execution: Inter-Process Communication (Named Pipes)" },
        { id: "T1078.002", name: "T1078.002 — Defense Evasion: Valid Accounts (Domain Accounts)" },
        { id: "T1059.001", name: "T1059.001 — Execution: PowerShell Command Interpreter (Distractor)" },
        { id: "T1105",     name: "T1105 — Command & Control: Ingress Tool Transfer (Distractor)" }
      ],
      answerKey: {
        relevantEventIds: ["EV-401", "EV-403", "EV-404", "EV-406", "EV-407", "EV-409", "EV-410", "EV-412"],
        timelineOrder: ["EV-401", "EV-403", "EV-404", "EV-406", "EV-407", "EV-409", "EV-410", "EV-412"],
        mitreMapping: {
          "EV-401": "T1046",
          "EV-403": "T1069.002",
          "EV-404": "T1021.001",
          "EV-406": "T1021.006",
          "EV-407": "T1021.002",
          "EV-409": "T1543.003",
          "EV-410": "T1055",
          "EV-412": "T1078.002"
        },
        causalPairs: [
          { cause: "EV-401", effect: "EV-403" },
          { cause: "EV-403", effect: "EV-404" },
          { cause: "EV-404", effect: "EV-406" },
          { cause: "EV-406", effect: "EV-407" },
          { cause: "EV-407", effect: "EV-409" },
          { cause: "EV-409", effect: "EV-410" },
          { cause: "EV-410", effect: "EV-412" }
        ],
        narrative: "An adversary on compromised workstation WS-DEV-04 executed network service scanning and domain admin discovery. The attacker pivoted via RDP to WS-OPS-12, invoked WinRM remote commands targeting DB-SRV-02, accessed SMB hidden admin shares (C$), and installed PsExec (PSEXESVC.exe). Utilizing named pipe IPC execution on DB-SRV-02, the attacker established an administrative pivot session directly to Domain Controller DC-01."
      }
    },


    /* ==========================================================================
       SCENARIO 5: THE MISSING RECORDS (Data Collection & Exfiltration) - NEW
       ========================================================================== */
    "missing-records": {
      id: "missing-records",
      categoryId: "data-collection-exfiltration",
      name: "The Missing Records",
      description: "Investigate database admin credential compromise, massive SQL query export, local file system discovery, multi-volume encrypted archive creation, base64 payload obfuscation, HTTPS exfiltration, and command-line log wipe scripts.",
      difficulty: "Advanced",
      estimatedTime: "12–18 minutes",
      status: "Available",
      brief: {
        caseId: "CASE-2026-EXFIL8802",
        title: "Operation Missing Records",
        target: "Enterprise File Repositories & Database Vaults",
        incidentDate: "2026-07-24 14:02:15 UTC",
        severity: "HIGH / CRITICAL",
        summary: "At 14:02 UTC, Database Activity Monitoring (DAM) and NetFlow telemetry flagged massive file reads, multi-volume 7z archive creation, Base64 header obfuscation, outbound HTTPS web service uploads to an unapproved cloud destination, and command-line log wipe scripts.",
        objective: "Examine 12 log telemetry artifacts, select the 8 attack events, discard 4 decoys, arrange the chronological attack flow, map MITRE ATT&CK techniques, establish causal links, and submit your report."
      },
      events: [
        {
          id: "EV-501",
          title: "Administrative Account Authenticated to Database Storage Host",
          timestamp: "2026-07-24 14:02:15",
          source: "Database Audit Logs",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Account db_admin logged into PostgreSQL database server DB-PROD-01 from management workstation WS-DEV-12 (10.0.8.44).",
          correctStep: 1,
          mitreId: "T1078.002",
          mitreName: "Valid Accounts: Domain Accounts"
        },
        {
          id: "EV-502",
          title: "Database Automatic Table Vacuum and Index Optimization Succeeded",
          timestamp: "2026-07-24 14:00:00",
          source: "PostgreSQL Service Engine",
          host: "DB-PROD-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "Scheduled maintenance job vacuumed 45 database tables with 0 warnings.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-503",
          title: "Unusually Large SQL Query Execution Exported High-Volume Customer Records",
          timestamp: "2026-07-24 14:08:40",
          source: "Database Activity Monitor (DAM)",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Query SELECT * FROM customer_pii_vault JOIN credit_cards ON customer_pii_vault.id = credit_cards.cust_id exported 850,000 sensitive records into C:\\Users\\Public\\cust_dump.csv.",
          correctStep: 2,
          mitreId: "T1005",
          mitreName: "Data from Local System / Database Repository"
        },
        {
          id: "EV-504",
          title: "Command-Line File Search Operations Executed Across Storage Drives",
          timestamp: "2026-07-24 14:15:00",
          source: "EDR Agent - DB-PROD-01",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Executed command: dir C:\\Users /s /b *.pem *.key *.p12 to discover stored private cryptographic keys and SSL certificates on disk.",
          correctStep: 3,
          mitreId: "T1083",
          mitreName: "File and Directory Discovery"
        },
        {
          id: "EV-505",
          title: "WSUS Patch Installation Completed on Database Server",
          timestamp: "2026-07-24 14:20:00",
          source: "Windows Update Agent",
          host: "DB-PROD-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "Security update package KB5034123 successfully installed on DB-PROD-01.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-506",
          title: "Multi-Volume Archive Created with Password Protection",
          timestamp: "2026-07-24 14:25:30",
          source: "EDR Process Execution - DB-PROD-01",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Executed CLI: 7z.exe a -v100m -pSuperSecret2026 C:\\Users\\Public\\db_backup.7z C:\\Users\\Public\\cust_dump.csv. Generated 8 encrypted split archive volumes.",
          correctStep: 4,
          mitreId: "T1560.001",
          mitreName: "Archive Data: Archive via Utility with Encryption"
        },
        {
          id: "EV-507",
          title: "System Utility Encoded Staged Archive Files into Obfuscated Format",
          timestamp: "2026-07-24 14:31:10",
          source: "Command Shell Audit",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Executed certutil.exe -encode C:\\Users\\Public\\db_backup.7z.001 C:\\Users\\Public\\encoded_part1.b64 to convert binary archive header into Base64 format.",
          correctStep: 5,
          mitreId: "T1132.001",
          mitreName: "Data Encoding: Standard Encoding"
        },
        {
          id: "EV-508",
          title: "Internal Network File Synchronization Succeeded",
          timestamp: "2026-07-24 14:35:00",
          source: "Robocopy System Log",
          host: "FS-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "Automated robocopy task mirrored public documentation directory from FS-01 to FS-02.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-509",
          title: "Outbound Encrypted HTTPS Connection Established to Cloud Endpoint",
          timestamp: "2026-07-24 14:40:05",
          source: "Perimeter Firewall Logs",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Process powershell.exe opened HTTPS web session from DB-PROD-01 (10.0.2.10) to external host 198.51.100.89:443 (sync-storage-cloud.net).",
          correctStep: 6,
          mitreId: "T1071.001",
          mitreName: "Command & Control: Web Protocols"
        },
        {
          id: "EV-510",
          title: "High Volume Encrypted Data Upload Transmitted Outbound",
          timestamp: "2026-07-24 14:45:50",
          source: "NetFlow Traffic Telemetry",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Host DB-PROD-01 transmitted 850 MB payload carrying Base64 encoded archives across 8 HTTP POST requests to remote IP 198.51.100.89.",
          correctStep: 7,
          mitreId: "T1048.003",
          mitreName: "Exfiltration Over Web Service"
        },
        {
          id: "EV-511",
          title: "Automated System Event Log Archival Completed",
          timestamp: "2026-07-24 14:50:00",
          source: "Windows Event Log Service",
          host: "DB-PROD-01",
          user: "SYSTEM",
          isRelevant: false,
          details: "System event log cleared oldest 1,000 entries into compressed EVTX archive per retention policy.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-512",
          title: "Command Line Indicator Deletion Executed on Staging Files",
          timestamp: "2026-07-24 14:52:15",
          source: "EDR Agent - DB-PROD-01",
          host: "DB-PROD-01",
          user: "db_admin",
          isRelevant: true,
          details: "Command line execution cmd.exe /c del /f /q C:\\Users\\Public\\cust_dump.csv C:\\Users\\Public\\*.7z* C:\\Users\\Public\\*.b64 executed to erase staging traces.",
          correctStep: 8,
          mitreId: "T1070.004",
          mitreName: "Indicator Removal: File Deletion"
        }
      ],
      mitreOptions: [
        { id: "T1078.002", name: "T1078.002 — Initial Access: Valid Accounts (Domain Accounts)" },
        { id: "T1005",     name: "T1005 — Collection: Data from Local System / Database" },
        { id: "T1083",     name: "T1083 — Discovery: File and Directory Discovery" },
        { id: "T1560.001", name: "T1560.001 — Archive Data: Archive via Utility with Encryption" },
        { id: "T1132.001", name: "T1132.001 — Defense Evasion: Data Encoding (Standard Encoding)" },
        { id: "T1071.001", name: "T1071.001 — Command & Control: Web Protocols (HTTPS)" },
        { id: "T1048.003", name: "T1048.003 — Exfiltration: Exfiltration Over Web Service" },
        { id: "T1070.004", name: "T1070.004 — Defense Evasion: Indicator Removal (File Deletion)" },
        { id: "T1021.001", name: "T1021.001 — Lateral Movement: Remote Desktop Protocol (Distractor)" },
        { id: "T1041",     name: "T1041 — Exfiltration Over C2 Channel (Distractor)" }
      ],
      answerKey: {
        relevantEventIds: ["EV-501", "EV-503", "EV-504", "EV-506", "EV-507", "EV-509", "EV-510", "EV-512"],
        timelineOrder: ["EV-501", "EV-503", "EV-504", "EV-506", "EV-507", "EV-509", "EV-510", "EV-512"],
        mitreMapping: {
          "EV-501": "T1078.002",
          "EV-503": "T1005",
          "EV-504": "T1083",
          "EV-506": "T1560.001",
          "EV-507": "T1132.001",
          "EV-509": "T1071.001",
          "EV-510": "T1048.003",
          "EV-512": "T1070.004"
        },
        causalPairs: [
          { cause: "EV-501", effect: "EV-503" },
          { cause: "EV-503", effect: "EV-504" },
          { cause: "EV-504", effect: "EV-506" },
          { cause: "EV-506", effect: "EV-507" },
          { cause: "EV-507", effect: "EV-509" },
          { cause: "EV-509", effect: "EV-510" },
          { cause: "EV-510", effect: "EV-512" }
        ],
        narrative: "An attacker authenticated as db_admin on DB-PROD-01 and executed a massive SQL JOIN query exporting 850,000 PII records to cust_dump.csv. The attacker searched local drives for cryptographic keys, compressed the dump into password-protected split 7z archives, and encoded the headers with Base64 using certutil.exe. PowerShell was then used to initiate an HTTPS upload of 850 MB to remote server 198.51.100.89, followed by command line deletion of staging files to clean evidence."
      }
    },


    /* ==========================================================================
       SCENARIO 6: THE MIDNIGHT ACCESS (Insider Threat) - NEW
       ========================================================================== */
    "midnight-access": {
      id: "midnight-access",
      categoryId: "insider-threat",
      name: "The Midnight Access",
      description: "Investigate an authorized employee off-hours workstation login, confidential HR compensation share access, bulk file staging into Projects_Temp, encrypted 7z archiving, unapproved USB flash drive mounting, physical exfiltration, and file wiping.",
      difficulty: "Advanced",
      estimatedTime: "12–18 minutes",
      status: "Available",
      brief: {
        caseId: "CASE-2026-INSIDER1102",
        title: "Operation Midnight Access",
        target: "Executive Confidential Vault & Workstation WS-HR-02",
        incidentDate: "2026-07-24 23:42:10 UTC",
        severity: "HIGH / CRITICAL",
        summary: "At 23:42 UTC (outside normal operating hours), physical access badges and endpoint telemetry recorded authorized employee workstation access. The user enumerated sensitive HR compensation repositories, staged 2.4 GB of confidential files, created an encrypted ZIP archive, copied data to an unapproved USB flash storage drive, and attempted to overwrite system access logs.",
        objective: "Examine 12 log telemetry artifacts, identify the 8 true attack events, reject 4 benign decoys, order the attack timeline chronologically, infer the correct MITRE ATT&CK techniques, link cause-and-effect pairs, and generate the final forensic analysis."
      },
      events: [
        {
          id: "EV-601",
          title: "Physical Building Access & Workstation Authentication Logged Outside Shift Hours",
          timestamp: "2026-07-24 23:42:10",
          source: "Physical Access Control & Windows Event ID 4624",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: true,
          details: "Employee e_watson swiped badge at executive floor turnstile and logged into workstation WS-HR-02 at 23:42 UTC (off-hours).",
          correctStep: 1,
          mitreId: "T1078",
          mitreName: "Valid Accounts"
        },
        {
          id: "EV-602",
          title: "Automated Workstation Screen Saver Lock Disengaged",
          timestamp: "2026-07-24 23:40:00",
          source: "Power Management API",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: false,
          details: "Display power management disengaged screen saver lock upon keyboard input.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-603",
          title: "File Explorer Enumeration of Sensitive HR Salary Share",
          timestamp: "2026-07-24 23:48:15",
          source: "File Audit Logs",
          host: "FS-HR-01",
          user: "e_watson",
          isRelevant: true,
          details: "User e_watson opened share \\\\FS-HR-01\\Confidential_Executive_Compensation\\ and accessed 480 executive compensation files.",
          correctStep: 2,
          mitreId: "T1005",
          mitreName: "Data from Local System / Network Share"
        },
        {
          id: "EV-604",
          title: "Bulk File Copy Executed to Local Staging Directory",
          timestamp: "2026-07-24 23:55:40",
          source: "EDR Agent - WS-HR-02",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: true,
          details: "Process robocopy.exe copied 2.4 GB of compensation spreadsheets into C:\\Users\\Public\\Projects_Temp\\.",
          correctStep: 3,
          mitreId: "T1074",
          mitreName: "Data Staged"
        },
        {
          id: "EV-605",
          title: "Local Printer Driver Status Diagnostic Succeeded",
          timestamp: "2026-07-25 00:02:00",
          source: "Print Spooler Audit",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: false,
          details: "Local USB printer driver status checked with 0 spooler errors.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-606",
          title: "Archive Utility Executed with Custom Cryptographic Key Flag",
          timestamp: "2026-07-25 00:08:20",
          source: "Sysmon Event ID 1",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: true,
          details: "Executed 7z.exe a -pInsiderPass2026! C:\\Users\\Public\\Projects_Temp\\exec_comp.zip C:\\Users\\Public\\Projects_Temp\\*.*.",
          correctStep: 4,
          mitreId: "T1560",
          mitreName: "Archive Collected Data: Archive via Utility"
        },
        {
          id: "EV-607",
          title: "Removable USB Storage Device Inserted and Mounted",
          timestamp: "2026-07-25 00:15:05",
          source: "Windows Plug and Play Audit (Sysmon Event ID 20001)",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: true,
          details: "Unapproved USB Flash Drive (Volume Label: MY_BACKUP, Serial: Kingston_902148) mounted on drive letter E:.",
          correctStep: 5,
          mitreId: "T1052.001",
          mitreName: "Exfiltration Over Physical Medium"
        },
        {
          id: "EV-608",
          title: "Cloud Storage Sync Agent Paused Notification Logged",
          timestamp: "2026-07-25 00:18:00",
          source: "OneDrive Client Agent",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: false,
          details: "OneDrive desktop sync paused by user setting for 2 hours.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-609",
          title: "High-Volume File Copy Executed to Removable Storage Drive",
          timestamp: "2026-07-25 00:22:30",
          source: "EDR File System Activity",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: true,
          details: "Process explorer.exe copied 2.4 GB file C:\\Users\\Public\\Projects_Temp\\exec_comp.zip to E:\\exec_comp.zip.",
          correctStep: 6,
          mitreId: "T1052.001",
          mitreName: "Exfiltration Over Physical Medium"
        },
        {
          id: "EV-610",
          title: "Unapproved USB Device Ejected and Safely Removed",
          timestamp: "2026-07-25 00:28:10",
          source: "Kernel PnP Notification",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: true,
          details: "Removable Storage Volume E: safely unmounted and physically disconnected from USB root hub.",
          correctStep: 7,
          mitreId: "T1052.001",
          mitreName: "Exfiltration Over Physical Medium"
        },
        {
          id: "EV-611",
          title: "System Clock Time Sync Updated with NTP Server",
          timestamp: "2026-07-25 00:30:00",
          source: "Windows Time Service (W32Time)",
          host: "WS-HR-02",
          user: "SYSTEM",
          isRelevant: false,
          details: "Time provider synchronized system clock with internal NTP stratum server ntp.targetcorp.local.",
          correctStep: null,
          mitreId: null,
          mitreName: null
        },
        {
          id: "EV-612",
          title: "Command Prompt Invoked to Overwrite Staging Directory",
          timestamp: "2026-07-25 00:34:15",
          source: "Command Shell Audit",
          host: "WS-HR-02",
          user: "e_watson",
          isRelevant: true,
          details: "Command executed: sdelete.exe -q -z C:\\Users\\Public\\Projects_Temp\\ to securely overwrite and erase local staging files.",
          correctStep: 8,
          mitreId: "T1070.004",
          mitreName: "Indicator Removal: File Deletion"
        }
      ],
      mitreOptions: [
        { id: "T1078",     name: "T1078 — Defense Evasion / Initial Access: Valid Accounts" },
        { id: "T1005",     name: "T1005 — Collection: Data from Local System / Network Share" },
        { id: "T1074",     name: "T1074 — Collection: Data Staged" },
        { id: "T1560",     name: "T1560 — Archive Collected Data: Archive via Utility" },
        { id: "T1052.001", name: "T1052.001 — Exfiltration: Exfiltration Over Physical Medium (USB)" },
        { id: "T1070.004", name: "T1070.004 — Defense Evasion: Indicator Removal (File Deletion)" },
        { id: "T1048.003", name: "T1048.003 — Exfiltration Over Web Service (Distractor)" },
        { id: "T1059.001", name: "T1059.001 — Execution: PowerShell Command Interpreter (Distractor)" }
      ],
      answerKey: {
        relevantEventIds: ["EV-601", "EV-603", "EV-604", "EV-606", "EV-607", "EV-609", "EV-610", "EV-612"],
        timelineOrder: ["EV-601", "EV-603", "EV-604", "EV-606", "EV-607", "EV-609", "EV-610", "EV-612"],
        mitreMapping: {
          "EV-601": "T1078",
          "EV-603": "T1005",
          "EV-604": "T1074",
          "EV-606": "T1560",
          "EV-607": "T1052.001",
          "EV-609": "T1052.001",
          "EV-610": "T1052.001",
          "EV-612": "T1070.004"
        },
        causalPairs: [
          { cause: "EV-601", effect: "EV-603" },
          { cause: "EV-603", effect: "EV-604" },
          { cause: "EV-604", effect: "EV-606" },
          { cause: "EV-606", effect: "EV-607" },
          { cause: "EV-607", effect: "EV-609" },
          { cause: "EV-609", effect: "EV-610" },
          { cause: "EV-610", effect: "EV-612" }
        ],
        narrative: "Employee E. Watson accessed the physical building and logged into workstation WS-HR-02 at 23:42 UTC outside normal working hours. Watson enumerated the confidential HR salary share, staged 2.4 GB of spreadsheets into C:\\Users\\Public\\Projects_Temp, and created a password-protected 7z archive. Watson then inserted an unapproved Kingston USB flash drive, copied the 2.4 GB archive directly to the physical medium, safely ejected the drive, and ran sdelete.exe to overwrite and erase all local staging traces."
      }
    }

  }
};
