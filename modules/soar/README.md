# SOAR & Automated Response

**Status: ✅ COMPLETE** — live end to end.

Wazuh alerts flow into an n8n workflow that filters, deduplicates,
enriches, asks an LLM for a short triage, and sends the result to Telegram.
The workflow stops there. A human reads the triage and decides what to do.

**Design principle: no autonomous response.** The pipeline never blocks an
IP, disables an account, or isolates a host. It produces a triage message
and a person acts on it. Automated containment is out of scope on purpose
until the triage quality is proven over a long period.

Workflow: **SOC Alert Triage** (n8n workflow ID `JZZ3TrGbgKEnV1Rp`, active).
The exported JSON lives at [`workflow-export.json`](workflow-export.json).

## Architecture

```text
Wazuh manager
  │  native "shuffle" integration hook
  │  filter: rule level >= 8, alert_format json
  ▼
POST /webhook/wazuh-alerts  (n8n)
  │
  ▼
[1] Webhook ──► [2] Severity Filter (Wazuh level >= 8)
                    │
                    ▼
               [3] Parse Alert (code)        extracts rule_id, rule_desc, level,
                    │                        agent_name, mitre, src_ip, file_hash,
                    │                        timestamp, dedup_key
                    ▼
               [4] Remove Duplicates         atomic, DB-backed, key = dedup_key
                    │
                    ▼
               [5] AbuseIPDB Enrichment      HTTP, reputation for src_ip
                    │
                    ▼
               [6] Merge (code, run once)    pulls enrichment itself, builds the
                    │                        LLM request body
                    ▼
               [7] AI Analysis               POST litellm /v1/chat/completions,
                    │                        model "Hermes Agent", 300 s timeout
                    ▼
               [8] Format Message (code)     strips markdown from the LLM text,
                    │                        builds a Telegram HTML message
                    │
                    ▼
               [9] Telegram Notify           sendMessage, parse_mode=HTML
                    │
                    ▼
            Human reads the triage and decides
```

## Node-by-node

| # | Node | Type | What it does | Why it is built this way |
|---|---|---|---|---|
| 1 | Wazuh Alert Webhook | Webhook (POST, path `wazuh-alerts`) | Receives the alert JSON from the Wazuh integration. | Single entry point; the path is the only Wazuh-side coupling. |
| 2 | Severity Filter | Filter | Passes items where `body.all_fields.rule.level >= 8`, the same Wazuh level the integration gates on. | A second check on the field the rest of the pipeline uses. If the integration config ever loosens, this node still holds the line. |
| 3 | Parse Alert | Code | Flattens the Shuffle payload into named fields and computes `dedup_key`. | Shuffle nests fields under `body.all_fields`, not `body.rule`. Parsing in one place means downstream nodes never care about the wrapper. |
| 4 | Remove Duplicates | Remove Duplicates (`removeItemsSeenInPreviousExecutions`) | Drops items whose `dedup_key` was seen in a previous execution (history 5000). The key is `rule_id` plus the alert timestamp truncated to the minute, so repeats inside a minute collapse and a later attack fires again. The agent name is not part of the key, so the same rule firing on two hosts within one minute produces one message. | Database-backed and atomic, so concurrent executions cannot both pass. |
| 5 | AbuseIPDB Enrichment | HTTP Request | Looks up `src_ip` reputation over the last 90 days. `neverError` is set so an API failure still produces a triage. The node runs for every alert; many alerts have no `src_ip`, so the request is sent with an empty `ipAddress` and the response is an error that the pipeline ignores. | Enrichment is advisory; it must not block the pipeline. |
| 6 | Merge | Code (run once) | Reads Parse Alert's output and the enrichment result via `$('AbuseIPDB Enrichment').first()`, then builds `llm_body` as a JSON string. | Runs exactly once per alert. Explained in the war story: multiple inbound wires to one node cause one execution per branch. |
| 7 | AI Analysis | HTTP Request | Sends `llm_body` to the local LLM gateway. | Model is `Hermes Agent` via litellm. The 300 s timeout exists because the upstream can hang rather than fail. |
| 8 | Format Message | Code | Removes markdown (`**`, `__`, backticks, headers) from the LLM text, turns bullets into `•`, truncates at 2800 characters and HTML-escapes it. Only the fixed header lines (alert title, rule, level, host, MITRE, time, "AI Triage") use `<b>`/`<i>`; the LLM sections are plain text. | Telegram HTML mode is strict. Stripping markdown and escaping the model output first avoids broken message rendering. |
| 9 | Telegram Notify | HTTP Request to the Bot API `sendMessage` | Sends the message to the analyst chat with `parse_mode=HTML`. Implemented as a raw HTTP call, not the Telegram node. | The human-in-the-loop endpoint. |

Latency from alert to Telegram message has not been measured as a figure.
The AI step dominates it: a production-sized triage prompt took 76 seconds
or more against the earlier model (see the war story, §4), and the node
timeout is 300 s.

## Integration

**Wazuh side.** The manager uses a native integration block:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://<your-n8n-host>/webhook/wazuh-alerts</hook_url>
  <level>8</level>
  <alert_format>json</alert_format>
</integration>
```

This block is configured through the Wazuh dashboard config editor, not by
editing `ossec.conf` on the host. In single-node docker the live config
sits on a named volume. Edits to the host bind-mount never reached the
running container. See the war story.

**n8n side.** The workflow is the only consumer of `/webhook/wazuh-alerts`.
Telegram delivers to a single analyst chat.

**Secrets: current state.** The bot token (in the Telegram Notify URL), the
AbuseIPDB key, and the litellm bearer token are set inline in the node
parameters of this workflow (HTTP Request header and URL fields), not in n8n
credential objects. The Telegram chat ID is a literal in two places: the
Format Message code node's output and the Telegram Notify request body. The
exported JSON replaces the values with `REDACTED`; in the exported Telegram
Notify body the `chat_id` is a bare `REDACTED` token, which is not a valid
expression until it is replaced with the numeric chat ID. Moving these to n8n
credentials is outstanding. By contrast, the separate Detection Gap Analyst
workflow does use n8n credential objects (see
`../detection-pipeline/docs/ai-detection-loop.md`).

## Sample triage output

Illustrative only. The layout follows the Format Message node (bold header
block, then the model's plain-text sections named in the prompt). The
address comes from an RFC 5737 documentation range, and the agent name,
timestamp and triage text are invented for the example.

> **SOC ALERT**
> _PowerShell with encoded command [T1059.001]_
>
> Rule: 100005   Level: 10
> Host: `win-victim-01`
> MITRE: T1059.001 (Execution)
> Time: 2026-09-27T03:13
>
> **AI Triage**
>
> WHAT HAPPENED
> `powershell.exe` launched with `-EncodedCommand`. The payload decodes to a
> short download-and-execute stub, source host `203.0.113.45`.
>
> TECHNIQUE
> T1059.001 — PowerShell. Obfuscated command-line execution.
>
> SEVERITY
> High. Encoded PowerShell from an interactive session is uncommon; the
> enrichment shows the source address has no abuse reports.
>
> NEXT STEPS
> • Decode the payload and check the URL it fetches.
> • Pull the parent process and logon session for `win-victim-01`.
> • Confirm whether the run was an authorised test.
>
> FP LIKELIHOOD
> Medium. Admin automation also uses encoded commands. Check against the
> change calendar before escalating.

## Lessons from the build

The full debugging story is in [`docs/war-story.md`](docs/war-story.md).
Seven stacked issues, including two of my own mistakes. Distilled
SOAR-specific lessons are in
[`shared/lessons-learned.md`](../../shared/lessons-learned.md#soar-build-lessons-module-4).

## Verification

- **Severity filter.** The filter gates on the Wazuh level, `body.all_fields.rule.level >= 8`.
  Validated end to end with a real attack: one Telegram message for a level-10 alert (rule 100005),
  and no message for level-3 noise. The filter was first written against `body.severity`, which is
  Shuffle's category rather than the Wazuh level. That mistake is in the war story.

## Re-importing the workflow

1. In n8n, open **Workflows → Import from file** and select
   `workflow-export.json`.
2. Every secret is exported as the literal text `REDACTED`. Fill them in
   before activating:
   - **AbuseIPDB Enrichment** — header `Key`: your AbuseIPDB API key.
   - **AI Analysis** — header `Authorization`: `Bearer <your litellm token>`.
   - **Telegram Notify** — the bot token in the URL path
     (`https://api.telegram.org/bot<token>/sendMessage`), and `chat_id` in the
     JSON body of the same node (a bare `REDACTED` in the export; replace it
     with the numeric chat ID).
   - **Format Message** — the `chat_id` string in the returned item.
3. Activate the workflow. The Webhook node shows the production URL. Point
   the Wazuh integration `hook_url` at it.

## Related

- [Detection Pipeline](../detection-pipeline/README.md) — the source of the alerts.
- [Adversary Emulation](../adversary-emulation/README.md) — the attacks that
  produced the real alerts used to test this pipeline.
- `shared/architecture.md` — platform-wide data flow.
