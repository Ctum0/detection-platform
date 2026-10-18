# VM and Asset Inventory

## Virtual Machines (Proxmox VE)

| VMID | Name | Role | OS | vCPU | RAM | Disk | Telemetry / Agent | Status |
|---|---|---|---|---|---|---|---|---|
| 100 | `linux-victim` | Linux victim | Ubuntu 22.04.5 | 2 | 2 GB | 32 GB | Wazuh Agent (`auth.log` / sshd) | On-demand (demo) |
| 101 | `windows-victim` | Windows victim | Windows 10 Pro | 2 | 4 GB | 32 GB | Wazuh Agent + Sysmon EID 1, 10, 13 | On-demand (demo) |
| 8000 | `ubuntu-cloud` | Cloud-init template | Ubuntu | 2 | 2 GB | 10 GB | None | Template |

> [!NOTE]
> **Resource Management & Operational State**:
> To conserve RAM on the Proxmox host (16 GB physical memory total), victim VMs are kept powered off during routine rule authoring and CI testing. Continuous testing is handled deterministically by the Tier 1 `wazuh-logtest` harness in CI without requiring VMs.
> 
> For live demonstrations and Tier 3 validation runs, start the VMs on Proxmox:
> ```bash
> qm start 100    # linux-victim
> qm start 101    # windows-victim
> ```
> Once booted, confirm both agents report active on the Wazuh manager:
> ```bash
> docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
> ```

## Physical Infrastructure

| Asset | Role | Specifications |
|---|---|---|
| Proxmox Host | Type-1 Hypervisor | 4 vCPU, 16 GB RAM |
| Analyst Workstation | Attacker / Control Plane | Parrot OS / Operator Console |

## Production Services (VPS & Control Plane)

| Service | Technology | Role |
|---|---|---|
| Wazuh SIEM | 4.14.8 (docker single-node) | Log ingestion, rule evaluation, alerting |
| Operator Console | FastAPI + Vanilla JS | Control plane: rule submission, review queue, validation dispatch |
| SOAR Engine | n8n | Webhook ingestion, alert enrichment, AI triage, Telegram notification |
| Runner | GitHub Actions Self-Hosted | Deploy runner on VPS (`deploy-wazuh.yml`, `attack-test.yml`) |

> [!IMPORTANT]
> **Splunk Clarification**:
> Only Wazuh is deployed. Splunk SPL queries are auto-generated during CI (`validate.yml`) to demonstrate that the Sigma detection library is multi-backend portable and not locked into Wazuh XML syntax. Splunk itself is not hosted.
