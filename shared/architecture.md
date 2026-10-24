# Architecture

## Overview

An end-to-end detection engineering and security operations platform.
Attacks are run in an isolated lab, telemetry flows into Wazuh,
Sigma is the single source of truth; CI converts it to Wazuh XML (deployed)
and Splunk SPL (generated, not deployed — a portability demonstration).
Investigations are supported by automation and AI. Every response action stays with a human analyst.

Only Wazuh is deployed. SPL is produced to prove the detection library is backend-portable.

## Architecture Diagram

![Detection Platform Architecture](../docs/images/architecture.png)

```mermaid
flowchart TB
    %% 1. Threat Emulation & Endpoint Telemetry
    subgraph LAB["1. Threat Emulation & Endpoints (Isolated Lab)"]
        ART["Adversary Emulation Engine\n(Atomic Red Team & Kali Linux)\nT1059 (PS), T1003 (LSASS), T1053"]
        WIN["Windows 10 Victim VM\n(SwiftOnSecurity Modular Sysmon)\nEID 1 (Process), EID 3 (Net), EID 13 (Reg), Sec 4624"]
        LNX["Ubuntu Linux Victim VM\n(Journald & Syslog)\n/var/log/auth.log & sudo"]
        AGT["Wazuh Endpoint Agent\n(Encrypted Transport Layer)\nmTLS over Tailscale (Port 1514)"]

        ART -->|"Executes TTPs"| WIN
        ART -->|"Executes TTPs"| LNX
        WIN -->|"Event Logs"| AGT
        LNX -->|"Syslog"| AGT
    end

    %% 2. Detection-as-Code CI/CD
    subgraph DAC["2. Detection-as-Code (DaC) CI/CD Pipeline"]
        GIT["Sigma Rule Library (Git)\ndetections/rules/*.yml (SSOT)"]
        CI["Automated CI Verification\n(GitHub Actions & PySigma Linter)\nSyntax & Schema Validation"]
        TRP["Multi-Backend Transpiler\npySigma Adapters\nSplunk SPL | Sentinel KQL | CrowdStrike CQL"]
        CD["CD Deployment Gate\nWazuh XML Synthesis & Packaging"]

        GIT -->|"Push / Pull Request"| CI
        CI -->|"Pass Lint"| TRP
        TRP -->|"Compile XML"| CD
    end

    %% 3. SIEM Core & Analytics
    subgraph SIEM["3. SIEM Core & Detection Engine (VPS Cloud)"]
        WZM["Wazuh SIEM Manager (v4.14.8)\n(Docker Single-Node / Analysisd Engine)\nXML Decoders + Custom Sigma Rules Engine"]
        IDX["Wazuh Indexer & Dashboard\n(OpenSearch Analytics Cluster)\nAlert Indexing, Storage & Visualizations"]

        WZM -->|"Index Alerts & Logs"| IDX
    end

    %% 4. SOC Control Plane & Operator Console
    subgraph CONSOLE["4. SOC Operator Console (Control Plane)"]
        API["Operator Console API\n(FastAPI Control Plane)"]
        IDE["Detection Studio IDE\n(Interactive Sigma Authoring & Transpiler Preview)"]
        SIM["Simulation Playground\n(Victimless EDR Telemetry Replay)"]
        REV["Review Queue & Governance\n(Two-Step Guarded Merge Approval)"]
        MTR["ATT&CK Matrix & Reporting\n(100% Proven Rules & Navigator JSON Export)"]

        API <-->|"Syntax Preview"| IDE
        API <-->|"Replay Testing"| SIM
        API <-->|"PR Management"| REV
        API <-->|"Heatmap Metrics"| MTR
    end

    %% 5. SOAR & Incident Triage
    subgraph SOAR["5. SOAR & Incident Triage (Automation)"]
        N8N["n8n SOAR Workflows\n(Automation Engine)\nAlert Deduplication & Routing"]
        INT["Threat Intelligence APIs\n(AbuseIPDB, VirusTotal, WHOIS)"]
        SOC["SOC Analyst Action Gate\n(Human-in-the-Loop)\nTelegram Alert & Containment Decision"]

        N8N <-->|"Enrich IP / Hash"| INT
        N8N -->|"Enriched Alert"| SOC
    end

    %% Cross-Subsystem Interconnections
    AGT ==>|"Forward Telemetry (mTLS 1514 over Tailscale)"| WZM
    CD ==>|"Auto-Deploy XML Rules (Manager API)"| WZM
    WZM ==>|"High-Severity Alert Webhook"| N8N
    REV -.->|"Merge Approved PR to main"| GIT
    API -.->|"Sync Rule & Alert Posture"| WZM

    %% Styling classes
    classDef lab fill:#f8fafc,stroke:#0284c7,stroke-width:1.5px,color:#0f172a;
    classDef dac fill:#f8fafc,stroke:#4f46e5,stroke-width:1.5px,color:#0f172a;
    classDef siem fill:#f8fafc,stroke:#16a34a,stroke-width:1.5px,color:#0f172a;
    classDef console fill:#f8fafc,stroke:#7c3aed,stroke-width:1.5px,color:#0f172a;
    classDef soar fill:#f8fafc,stroke:#d97706,stroke-width:1.5px,color:#0f172a;

    class ART,WIN,LNX,AGT lab;
    class GIT,CI,TRP,CD dac;
    class WZM,IDX siem;
    class API,IDE,SIM,REV,MTR console;
    class N8N,INT,SOC soar;
```

## Network

The lab runs on a private network. Victims and the hypervisor sit on a
home LAN, and remote administration and telemetry traverse a private
overlay network. Addresses are not published here.

Wazuh manager agent ports are bound to the Tailscale interface only; the API
is loopback-only.

## Components

| Component | Technology | Host |
|---|---|---|
| Hypervisor | Proxmox VE | Bare-metal server |
| Linux victim | Ubuntu 22.04 + Wazuh agent | VM |
| Windows victim | Windows 10 Pro + Sysmon (SwiftOnSecurity config) + Wazuh agent | VM |
| SIEM | Wazuh 4.14.8 (docker single-node) | VPS |
| SOAR | n8n (workflow automation) | VPS |
| Attacker | Parrot OS | Analyst laptop |
| Detection repository | GitHub | Cloud |
