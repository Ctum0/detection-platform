# Detection Platform — Demo Runbook & Video Script

This runbook documents how to demonstrate the detection platform end-to-end, from human or AI rule submission to automated CI/CD deployment, live attack execution, and SOAR triage.

---

## 3-Tier Testing Architecture

The platform separates testing into three deliberate tiers to guarantee correctness without requiring always-on lab infrastructure:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        3-Tier Validation Story                         │
├────────────────────────────────┬───────────────────────────────────────┤
│ Tier 1: Deterministic CI       │ wazuh-logtest against committed       │
│ (GitHub-hosted runner, seconds)│ sample JSON events (10/10 verified)   │
├────────────────────────────────┼───────────────────────────────────────┤
│ Tier 2: Unit & Converter Tests │ pytest platform/tests                 │
│ (Local / GitHub Actions)       │ XML linting, ID mapping, rule anchors │
├────────────────────────────────┼───────────────────────────────────────┤
│ Tier 3: Live Attack Runner     │ attack-tests/ on victim VMs via       │
│ (Self-hosted runner, on-demand)│ Atomic Red Team / attack-test.yml     │
└────────────────────────────────┴───────────────────────────────────────┘
```

---

## Live Demo Runbook (3 Steps)

### Pre-Demo Checklist (5 Minutes Before Demo)
1. **Console**: Confirm Operator Console is accessible at `http://localhost:8000` (or your deployment URL) and unlocked.
2. **Victims (Optional for Tier 3)**: If demonstrating live VM execution, start the Proxmox VMs:
   ```bash
   qm start 100    # linux-victim
   qm start 101    # windows-victim
   ```
   Verify agents are active:
   ```bash
   docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
   ```
   *(Note: If VMs are off, Tier 1 deterministic logtest proves every rule in seconds with 0 RAM overhead).*

---

### Step 1: Submit or Select a Detection Rule in Operator Console
1. Open the Operator Console web UI at `http://localhost:8000`.
2. Navigate to **Submit rule** (`#/submit`) in the sidebar.
3. Paste a Sigma detection rule (or upload a `.yml` file), enter slug and rationale, and click **Validate Rule**.
   - The console runs local syntax validation and verifies that log sources map to Wazuh telemetry channels.
4. Click **Submit as PR**.
   - The console creates branch `rule/<slug>`, commits to `detections/sigma/<slug>.yml`, opens a pull request on GitHub, and registers the proposal into the unified review queue.
5. In **Review queue** (`#/queue`), review the proposal:
   - Notice the **Multi-Backend Artifacts** tab displaying **Sigma (YAML)**, **Wazuh XML**, and **Splunk SPL**.
   - Note the **Origin** badge displaying **Human** vs **AI**.

---

### Step 2: Automated CI/CD & Deploy Gate
1. Click **Approve** on the proposal.
2. The merge gate checks GitHub Actions CI:
   - `validate.yml`: Runs `sigma check` and generates Splunk SPL queries to prove multi-backend portability.
   - Pull request is merged to `main`.
3. Merging triggers `convert-deploy.yml`:
   - Translates Sigma to Wazuh XML using `sigma_to_wazuh.py`.
   - Merges into `detections/wazuh/custom_rules.xml` using `merge_wazuh_rules.py`.
   - Assigns persistent rule IDs via `platform/converters/wazuh_rule_ids.json`.
   - Triggers `deploy-wazuh.yml` on the self-hosted runner.
4. `deploy-wazuh.yml`:
   - Backs up existing `local_rules.xml`.
   - Pushes rules to Wazuh Manager API (`PUT /rules/files/local_rules.xml`).
   - Restarts manager (`docker restart single-node-wazuh.manager-1`) and verifies zero XML parse errors.

---

### Step 3: Run Validation & Witness Alert Firing
1. In the Operator Console, open the merged proposal and click **Run validation**:
   - Dispatches `.github/workflows/attack-test.yml` on the self-hosted runner.
2. Alternatively, run the deterministic **Tier 1 Logtest** suite:
   ```bash
   python3 tests/rule-tests/run_logtest.py
   ```
   - Watch all 10 deployable detections fire their exact expected rule IDs against `wazuh-logtest`.
3. Live Detection & SOAR Execution:
   - The attack executes on the target victim.
   - Wazuh Manager detects the attack and generates an alert.
   - For rule levels ≥ 8, the Wazuh integration hook invokes the **n8n SOAR webhook**.
   - The 9-node SOAR workflow queries threat intel, extracts MITRE technique metadata, generates an AI analyst briefing, and posts the alert to Telegram.
4. Purple-team loop closed: Click **Record validation** in the Operator Console with the fired alert details.

---

## 2–3 Minute Video Script (Screen Recording)

### Scene 1: Introduction (0:00 - 0:30)
- **Visual**: Show Operator Console Overview dashboard (`#/overview`) showing 10/10 validated detections, pipeline status operational, and recent activity.
- **Narrator**:
  > *"Welcome. This is the Detection Engineering & Operations Platform. Detection engineering often struggles with two major issues: rules that sit untested in repositories, and disconnects between rule authors and deployed SIEM engines.
  > Here, Sigma is our single source of truth. The Operator Console is our control plane: human analysts and AI agents submit detections into one unified pipeline that validates syntax, converts to multi-backend formats, deploys to Wazuh, and verifies execution against real attacks."*

### Scene 2: Rule Submission & Multi-Backend Artifacts (0:30 - 1:15)
- **Visual**: Navigate to **Submit rule** (`#/submit`). Paste a sample Sigma rule (e.g. `t1547_001_registry_run_key`). Click **Validate**, show green feedback, and click **Submit as PR**. Jump to **Review queue** (`#/queue`).
- **Narrator**:
  > *"Here in the console, we author or review detection rules. When an analyst or AI submits a rule, the console validates the log sources, creates a Git branch, and opens a pull request.
  > Look at the proposal card: our console immediately surfaces multi-backend artifacts. From one single Sigma definition, we have the native Sigma YAML, the compiled Wazuh XML rule block, and the generated Splunk SPL query proving our detections are completely portable across SIEM backends."*

### Scene 3: Deterministic CI Validation & Deployment (1:15 - 1:50)
- **Visual**: Show GitHub Actions running `rule-tests.yml` and `convert-deploy.yml`. In terminal, execute `python3 tests/rule-tests/run_logtest.py` showing 10/10 PASS.
- **Narrator**:
  > *"Before any rule reaches production, it passes through our 3-tier testing architecture. 
  > Tier 1 is our deterministic CI test: using wazuh-logtest inside an ephemeral manager container, we replay committed sample telemetry to prove every rule in the library fires as expected. It runs in seconds without needing victim VMs.
  > Once approved, our CD workflow safely pushes the custom rules to the live Wazuh manager API and verifies zero syntax degradation."*

### Scene 4: Live Attack, Alert & SOAR Telegram Triage (1:50 - 2:30)
- **Visual**: Click **Run validation** in the console. Cut to Wazuh Dashboard showing the rule firing at Level 10. Cut to Telegram showing the automated SOAR alert with AI enrichment.
- **Narrator**:
  > *"Now for the final verification: we click 'Run validation' in the console. The attack runs against our victim endpoint, Wazuh detects the activity, and because the rule is high severity, our n8n SOAR pipeline immediately triggers.
  > Within seconds, our Telegram channel receives a structured alert triage: MITRE ATT&CK mapping, endpoint context, and AI risk analysis—empowering the human analyst to make an informed response decision.
  > That completes the loop: from Sigma code to proven alert in under three minutes."*
