#!/usr/bin/env python3
"""Sigma -> Wazuh XML converter for this detection platform.

Converts detections/sigma/*.yml into a single Wazuh custom rules file
(detections/wazuh/custom_rules.xml) with stable IDs starting at 100001.

Approach adapted from Alanv0303/Rule-converter (MIT): parse multi-doc
Sigma YAML, translate selections into Wazuh <field>/<match> checks, emit
one XML <rule> per convertible doc. Extended here with repo-specific
rules: per-logsource anchoring (if_sid/if_group + groups), Sigma->Wazuh field
mapping, MITRE blocks, event_count correlations via frequency/timeframe,
and an ID-mapping header comment.

Usage (run from the repo root):
  python3 platform/converters/sigma_to_wazuh.py
  python3 platform/converters/sigma_to_wazuh.py \\
      --sigma-dir detections/sigma \\
      --output detections/wazuh/custom_rules.xml \\
      --start-id 100001
  python3 platform/converters/sigma_to_wazuh.py --anchor if_group   # Wazuh 4.9.0+

Requirements: python3 + pyyaml. No sigma-cli needed.

Limitations (review before deploying to production):
- Sigma is more expressive than Wazuh rules; output is a tested starting
  point, not a 1:1 translation. Validate with wazuh-logtest.
- temporal/temporal_ordered correlations have no Wazuh equivalent and are
  SKIPPED (ssh_success_after_failures.yml).
- Wazuh <field> checks AND together; same-field alternations are folded
  into one PCRE2 alternation to preserve Sigma OR semantics.
- Stock parent SIDs (61603 = Sysmon EID 1, 61612 = Sysmon EID 10, from
  wazuh-ruleset 0595-win-sysmon_rules.xml) are assumed. On Wazuh 4.9.0+,
  if_sid chaining off level-0 sysmon parents silently fails at runtime
  (wazuh/wazuh#36029) -- use --anchor if_group there.
"""

import argparse
import datetime
import re
import sys
from pathlib import Path
from xml.dom import minidom

import yaml
import xml.etree.ElementTree as ET

# --------------------------------------------------------------------------
# Static mapping tables
# --------------------------------------------------------------------------

# Sigma field -> Wazuh decoded field (windows_eventchannel decoder).
FIELD_MAP = {
    "Image": "win.eventdata.image",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "TargetImage": "win.eventdata.targetImage",
    "SourceImage": "win.eventdata.sourceImage",
    "GrantedAccess": "win.eventdata.grantedAccess",
    "TargetFilename": "win.eventdata.targetFilename",
    "ImagePath": "win.eventdata.imagePath",
    "ServiceName": "win.eventdata.serviceName",
    "DestinationIp": "win.eventdata.destinationIp",
    "TargetObject": "win.eventdata.targetObject",
    "Details": "win.eventdata.details",
    "EventType": "win.eventdata.eventType",
    "ImageLoaded": "win.eventdata.imageLoaded",
    "OriginalFileName": "win.eventdata.originalFileName",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
    "User": "win.eventdata.user",
    "EventID": "win.system.eventID",
}

# Stock Wazuh sysmon parents (0595-win-sysmon_rules.xml, 4.x ruleset).
SYSMON_PARENTS = {
    1: {"sid": "61603", "group": "sysmon_event1"},
    7: {"sid": "61609", "group": "sysmon_event7"},
    10: {"sid": "61612", "group": "sysmon_event_10"},
    11: {"sid": "61613", "group": "sysmon_event_11"},
    12: {"sid": "61614", "group": "sysmon_event_12"},
    13: {"sid": "61615", "group": "sysmon_event_13"},
    14: {"sid": "61616", "group": "sysmon_event_14"},
}

# Sigma Sysmon category -> default Sysmon event ID (verified against the live
# 0595-win-sysmon_rules.xml, Wazuh 4.14).
SYSMON_CATEGORY_EID = {
    "process_creation": 1,
    "image_load": 7,
    "process_access": 10,
    "file_event": 11,
    "registry_add": 12,
    "registry_delete": 12,
    "registry_set": 13,
    "registry_rename": 14,
}

SIGMA_LEVEL_TO_WAZUH = {
    "informational": 5,
    "low": 5,
    "medium": 7,
    "high": 10,
    "critical": 12,
}

# Technique -> (tactic, technique display name) for the <mitre> block.
# Tactic is resolved from the rule's own tags first (tactic_of); this table
# is the fallback. NOTE: MITRE restructured log-clearing in 2026 -- the old
# T1070.001 (Indicator Removal) is now T1685.005 (Disable or Modify Tools)
# under the current tactic "Defense Impairment" (verified live 2026-09-26).
MITRE = {
    "T1059.001": ("Execution", "PowerShell"),
    "T1059.004": ("Execution", "Unix Shell"),
    "T1003.001": ("Credential Access", "LSASS Memory"),
    "T1136.001": ("Persistence", "Local Account"),
    "T1053.005": ("Persistence", "Scheduled Task"),
    "T1543.003": ("Persistence", "Windows Service"),
    "T1547.001": ("Persistence", "Registry Run Keys / Startup Folder"),
    "T1548.001": ("Privilege Escalation", "Setuid and Setgid"),
    "T1110.001": ("Credential Access", "Password Guessing"),
    "T1685.005": ("Defense Impairment", "Clear Windows Event Logs"),
    "T1098": ("Execution", "T1098"),  # canary test technique; display name unresolved
    "T1070.001": ("Defense Evasion", "Clear Windows Event Logs"),  # legacy ID
}

# Tactic display names, keyed by TA-ID and by shortname. Shortnames follow
# current MITRE (e.g. defense-impairment); legacy taXXXX IDs kept working.
TACTIC_DISPLAY = {
    "ta0001": "Reconnaissance",
    "ta0002": "Execution",
    "ta0003": "Persistence",
    "ta0004": "Privilege Escalation",
    "ta0005": "Defense Evasion",
    "ta0006": "Credential Access",
    "ta0007": "Discovery",
    "ta0008": "Lateral Movement",
    "ta0009": "Collection",
    "ta0010": "Exfiltration",
    "ta0011": "Command and Control",
    "ta0040": "Impact",
    "ta0042": "Resource Development",
    "ta0043": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "defense-impairment": "Defense Impairment",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "command-and-control": "Command and Control",
    "impact": "Impact",
}

SKIP_FILES = {
    # temporal_ordered has no Wazuh frequency/timeframe equivalent.
    "ssh_success_after_failures.yml": "temporal_ordered correlation unsupported by Wazuh",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def technique_of(doc):
    for tag in doc.get("tags", []):
        m = re.fullmatch(r"attack\.(t\d{4}\.\d{3})", str(tag))
        if m:
            return "T" + m.group(1)[1:].upper()
    for tag in doc.get("tags", []):
        m = re.fullmatch(r"attack\.(t\d{4})", str(tag))
        if m:
            return "T" + m.group(1)[1:].upper()
    return "Unknown"


def tactic_of(doc, technique):
    """Resolve tactic display name from the rule's own tags first, so MITRE
    restructures (e.g. Defense Evasion -> Defense Impairment) flow through
    without code changes. Falls back to the static MITRE table."""
    for tag in doc.get("tags", []):
        t = str(tag)
        if not t.startswith("attack."):
            continue
        key = t[len("attack"):].lower().replace("_", "-")
        if key in TACTIC_DISPLAY:
            return TACTIC_DISPLAY[key]
    return MITRE.get(technique, ("Unknown", technique))[0]


def technique_name(technique):
    return MITRE.get(technique, (None, technique))[1]


def split_field_op(key):
    """'Image|endswith' -> ('Image', 'endswith'); 'EventID' -> ('EventID', None)."""
    if "|" in key:
        field, _, op = key.partition("|")
        return field, op
    return key, None


def pcre2_alt(values, prefix="", suffix=""):
    """Fold alternation into one case-insensitive PCRE2 pattern."""
    inner = "|".join(re.escape(str(v)) for v in values)
    return f"(?i){prefix}(?:{inner}){suffix}"


def contains_pattern(values):
    # Wazuh <field> is already substring matching, but an explicit PCRE2
    # alternation is unambiguous and matches stock custom-rule style.
    return pcre2_alt(values, prefix=".*", suffix=".*")


def endswith_pattern(values):
    return pcre2_alt(values, suffix="$")


def exact_pattern(values):
    return pcre2_alt(values, prefix="^", suffix="$")


def startswith_pattern(values):
    return pcre2_alt(values, prefix="^")


def contains_all_pattern(values):
    # One PCRE2 lookahead per value: every value must appear, in any order.
    return "(?i)^" + "".join(f"(?=.*{re.escape(str(v))})" for v in values)


def resolve_condition(condition, names):
    """Translate a Sigma condition into [(selection_name, negated), ...].

    Only conjunctions are supported: `a and b`, `not f`, `all of x*`, and
    `1 of x*` when it matches exactly one item. Returns a reason string for
    anything else (or, parentheses, ambiguous `1 of`), because emitting a
    wrong rule is worse than skipping one."""
    if not isinstance(condition, str) or not condition.strip():
        return "missing or non-string condition"
    text = condition.strip()
    if re.search(r"[()]|\bor\b|\|", text):
        return f"condition '{text}' uses or/parentheses (not translatable to one Wazuh rule)"
    out = []
    for part in re.split(r"\s+and\s+", text):
        part = part.strip()
        negated = part.startswith("not ")
        if negated:
            part = part[4:].strip()
        m = re.fullmatch(r"(all|1|any) of (\S+)", part)
        if m:
            quant, pat = m.groups()
            hits = [n for n in names if (n.startswith(pat[:-1]) if pat.endswith("*") else n == pat)]
            if not hits:
                return f"'{part}' matches no detection item"
            if quant != "all" and len(hits) > 1:
                return f"'{part}' is an OR over {len(hits)} items (not translatable to one Wazuh rule)"
            if negated and quant == "all" and len(hits) > 1:
                return f"'not {part}' negates a conjunction (not translatable)"
            out.extend((h, negated) for h in hits)
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):
            if part not in names:
                return f"condition references undefined item '{part}'"
            out.append((part, negated))
        else:
            return f"unsupported condition fragment '{part}'"
    return out


def add_field(rule_el, wazuh_field, pattern, use_regex=True):
    f = ET.SubElement(rule_el, "field")
    f.set("name", wazuh_field)
    if use_regex:
        f.set("type", "pcre2")
    f.text = pattern
    return f


def add_mitre(rule_el, doc, technique):
    # Wazuh's <mitre> block only accepts <id> (4.14 analysisd rejects
    # <tactic>/<technique> with "Invalid option"); Wazuh resolves the tactic
    # and name from its own MITRE database.
    m = ET.SubElement(rule_el, "mitre")
    ET.SubElement(m, "id").text = technique


def finish_rule(rule_el, doc, technique):
    desc = ET.SubElement(rule_el, "description")
    desc.text = f"{doc.get('title', 'Sigma detection')} [{technique}]"
    add_mitre(rule_el, doc, technique)


def parse_timespan(span):
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(span).strip())
    if not m:
        raise ValueError(f"Cannot parse timespan: {span!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


# --------------------------------------------------------------------------
# Per-logsource translators. Each returns True if it emitted the rule body.
# --------------------------------------------------------------------------

def translate_windows(rule_el, doc, anchor):
    """Sysmon + Windows Security/System channel rules -> win.* fields.

    Returns True when the rule body was emitted, False for a log source this
    translator does not handle, or a reason string when the rule cannot be
    expressed faithfully (it is then skipped rather than emitted wrong)."""
    logsource = doc.get("logsource", {})
    detection = doc.get("detection", {})
    category = logsource.get("category")
    service = logsource.get("service")

    if category in SYSMON_CATEGORY_EID:
        event_id = None
        for sel in detection.values():
            if isinstance(sel, dict) and "EventID" in sel:
                event_id = sel["EventID"]
        event_id = event_id if event_id in SYSMON_PARENTS else SYSMON_CATEGORY_EID[category]
        parent = SYSMON_PARENTS[event_id]
        anchor_el = ET.SubElement(
            rule_el, "if_sid" if anchor == "if_sid" else "if_group"
        )
        anchor_el.text = parent["sid"] if anchor == "if_sid" else parent["group"]
        grp = ET.SubElement(rule_el, "group")
        grp.text = f"{parent['group']},"
    elif service in ("security", "system"):
        channel = "Security" if service == "security" else "System"
        add_field(rule_el, "win.system.channel", f"^{channel}$", use_regex=False)
        grp = ET.SubElement(rule_el, "group")
        grp.text = (
            "windows_security," if service == "security" else "windows_system,"
        )
    else:
        return False

    names = [k for k in detection if k != "condition"]
    plan = resolve_condition(detection.get("condition"), names)
    if isinstance(plan, str):
        return plan

    for sel_name, negated in plan:
        sel = detection[sel_name]
        if not isinstance(sel, dict):
            return f"item '{sel_name}' is not a field mapping (keyword lists are not translatable)"
        if negated and len(sel) != 1:
            # NOT (a AND b) cannot be written as per-field negation.
            return f"'not {sel_name}' has {len(sel)} fields; only single-field filters can be negated"
        for key, value in sel.items():
            field, op = split_field_op(key)
            if field not in FIELD_MAP:
                return f"field '{field}' has no Wazuh mapping"
            values = value if isinstance(value, list) else [value]
            wfield = FIELD_MAP[field]
            if field == "EventID":
                if negated:
                    return "negated EventID is not supported"
                add_field(rule_el, wfield, f"^{values[0]}$", use_regex=False)
                continue
            if op == "endswith":
                pattern = endswith_pattern(values)
            elif op == "startswith":
                pattern = startswith_pattern(values)
            elif op == "contains|all":
                pattern = contains_all_pattern(values)
            elif op == "re":
                if len(values) != 1:
                    return f"'{key}' has several regexes"
                pattern = str(values[0])
            elif op in ("contains", None) and field != "GrantedAccess":
                pattern = contains_pattern(values)
            elif op is None or op == "contains":  # GrantedAccess: exact-mask semantics.
                pattern = exact_pattern(values)
            else:
                return f"operator '{op}' is not supported"
            f_el = add_field(rule_el, wfield, pattern)
            if negated:
                f_el.set("negate", "yes")
    return True


def translate_sshd(rule_el, doc):
    """auth.log sshd lines -> full_log PCRE2 match (decoder-independent)."""
    detection = doc.get("detection", {})
    needles = []
    for sel in detection.values():
        if isinstance(sel, list):
            # Bare-string list form (e.g. selection: ['Failed password']).
            needles.extend(str(v) for v in sel)
            continue
        if not isinstance(sel, dict):
            continue
        for key, value in sel.items():
            field, _ = split_field_op(key)
            if field in ("message",):
                vals = value if isinstance(value, list) else [value]
                needles.extend(vals)
    if not needles:
        return False
    m = ET.SubElement(rule_el, "match")
    m.set("type", "pcre2")
    m.text = "(?i)sshd\\[\\d+\\]: (?:{})".format(
        "|".join(re.escape(str(n)) for n in needles)
    )
    grp = ET.SubElement(rule_el, "group")
    grp.text = "syslog,sshd,"
    return True


def translate_auditd(rule_el, doc):
    """auditd EXECVE -> full_log PCRE2 match over exe + argv patterns."""
    detection = doc.get("detection", {})
    exes, args = [], []
    for sel in detection.values():
        if not isinstance(sel, dict):
            continue
        for key, value in sel.items():
            field, op = split_field_op(key)
            vals = value if isinstance(value, list) else [value]
            if field == "exe":
                exes.extend(str(v).split("/")[-1] for v in vals)
            elif field in ("type",):
                continue
            elif field.startswith("a"):
                args.extend(vals)
    if not exes:
        return False
    m = ET.SubElement(rule_el, "match")
    m.set("type", "pcre2")
    exe_pat = "(?:{})".format(
        "|".join(re.escape(e) for e in dict.fromkeys(exes))
    )
    if args:
        arg_pat = "|".join(
            re.escape(str(a)).replace(r"\ ", ".*") for a in dict.fromkeys(args)
        )
        # Both the binary and a suspicious argument must appear in the
        # same EXECVE record; argv order varies so match independently.
        m.text = f"(?i){exe_pat}.*(?:{arg_pat})"
    else:
        m.text = f"(?i){exe_pat}"
    grp = ET.SubElement(rule_el, "group")
    grp.text = "auditd,"
    return True


def rule_class(doc):
    logsource = doc.get("logsource", {})
    product = logsource.get("product")
    service = logsource.get("service")
    category = logsource.get("category")
    if product == "windows":
        return "windows"
    if product == "linux" and service == "auth":
        return "sshd"
    if product == "linux" and service == "auditd":
        return "auditd"
    if category in ("process_creation", "process_access"):
        return "windows"
    return "unknown"


# --------------------------------------------------------------------------
# Main conversion
# --------------------------------------------------------------------------

def convert(sigma_dir, start_id, anchor):
    rules_out = []  # (rule_el, pre_comment)
    mapping = []    # (rule_id, sigma_file, title) for the header comment
    skipped = []
    rule_id = start_id

    for path in sorted(sigma_dir.glob("*.yml")):
        if path.name in SKIP_FILES:
            skipped.append((path.name, SKIP_FILES[path.name]))
            continue
        docs = [d for d in yaml.safe_load_all(path.read_text()) if d]
        pending_base_id = {}
        for doc in docs:
            title = doc.get("title", path.stem)
            technique = technique_of(doc)
            level = SIGMA_LEVEL_TO_WAZUH.get(str(doc.get("level", "")).lower(), 7)

            if "correlation" in doc:
                corr = doc["correlation"]
                ctype = corr.get("type")
                if ctype == "event_count":
                    base_name = (corr.get("rules") or [None])[0]
                    base_id = pending_base_id.get(base_name)
                    if base_id is None:
                        print(
                            f"WARN: {path.name}: correlation references "
                            f"unknown base {base_name!r}; skipped",
                            file=sys.stderr,
                        )
                        skipped.append((f"{path.name}#{title}", "unresolved base"))
                        continue
                    timespan = parse_timespan(corr.get("timespan", "10m"))
                    threshold = (corr.get("condition") or {}).get("gte") or (
                        corr.get("condition") or {}
                    ).get("gt", 0)
                    rule_el = ET.Element("rule")
                    rule_el.set("id", str(rule_id))
                    rule_el.set("level", str(level))
                    rule_el.set("frequency", str(int(threshold)))
                    rule_el.set("timeframe", str(timespan))
                    ET.SubElement(rule_el, "if_matched_sid").text = str(base_id)
                    if "src_ip" in (corr.get("group-by") or []):
                        ET.SubElement(rule_el, "same_source_ip")
                    grp = ET.SubElement(rule_el, "group")
                    grp.text = "syslog,sshd,"
                    finish_rule(rule_el, doc, technique)
                    rules_out.append((rule_el, f"{title} | {path.name}"))
                    mapping.append((rule_id, path.name, title))
                    rule_id += 1
                else:
                    skipped.append((f"{path.name}#{title}", f"{ctype} unsupported"))
                continue

            rule_el = ET.Element("rule")
            rule_el.set("id", str(rule_id))
            rule_el.set("level", str(level))
            cls = rule_class(doc)
            ok = (
                translate_windows(rule_el, doc, anchor)
                if cls == "windows"
                else translate_sshd(rule_el, doc)
                if cls == "sshd"
                else translate_auditd(rule_el, doc)
                if cls == "auditd"
                else False
            )
            if ok is not True:
                reason = ok if isinstance(ok, str) else f"unhandled logsource {doc.get('logsource')}"
                print(f"WARN: {path.name}: {reason}; skipped", file=sys.stderr)
                skipped.append((f"{path.name}#{title}", reason))
                continue
            finish_rule(rule_el, doc, technique)
            if doc.get("name"):
                pending_base_id[doc["name"]] = rule_id
            rules_out.append((rule_el, f"{title} | {path.name}"))
            mapping.append((rule_id, path.name, title))
            rule_id += 1

    return rules_out, mapping, skipped


def _comment_safe(text):
    """XML comments may not contain "--" (it makes the file unparseable)."""
    return re.sub(r"-{2,}", "-", str(text))


def render(rules_out, mapping, skipped, start_id):
    lines = []
    lines.append("<!--")
    lines.append("  Detection Platform custom Wazuh rules. GENERATED FILE: do not")
    lines.append("  edit by hand; regenerate with: python3 platform/converters/sigma_to_wazuh.py")
    lines.append(f"  Generated (UTC): {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M}")
    lines.append("  Rule ID <-> Sigma rule mapping:")
    for rid, fname, title in mapping:
        fname, title = _comment_safe(fname), _comment_safe(title)
        lines.append(f"    {rid} <-> {fname} :: {title}")
    lines.append("  Skipped (no Wazuh equivalent):")
    if skipped:
        for name, reason in skipped:
            lines.append(f"    SKIP {name}: {_comment_safe(reason)}")
    else:
        lines.append("    (none)")
    lines.append("-->")

    body = ['<group name="detection_platform_sigma,">']
    for rule_el, comment in rules_out:
        pretty = minidom.parseString(ET.tostring(rule_el, encoding="unicode")).toprettyxml(indent="  ")
        inner = "\n".join(
            line for line in pretty.splitlines()[1:] if line.strip()
        )
        body.append(f"  <!-- {_comment_safe(comment)} -->")
        body.append("  " + inner.replace("\n", "\n  "))
    body.append("</group>")
    return "\n".join(lines) + "\n" + "\n".join(body) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Convert Sigma rules to Wazuh XML.")
    ap.add_argument("--sigma-dir", default="detections/sigma")
    ap.add_argument("--output", default="detections/wazuh/custom_rules.xml")
    ap.add_argument("--start-id", type=int, default=100001)
    ap.add_argument(
        "--anchor",
        choices=["if_sid", "if_group"],
        default="if_sid",
        help="Sysmon anchoring; use if_group on Wazuh 4.9.0+ (wazuh/wazuh#36029).",
    )
    args = ap.parse_args()

    sigma_dir = Path(args.sigma_dir)
    rules_out, mapping, skipped = convert(sigma_dir, args.start_id, args.anchor)
    Path(args.output).write_text(render(rules_out, mapping, skipped, args.start_id))
    print(f"Wrote {len(rules_out)} rules to {args.output} (IDs {args.start_id}-{args.start_id + len(rules_out) - 1})")
    for name, reason in skipped:
        print(f"SKIP {name}: {reason}")


if __name__ == "__main__":
    main()
