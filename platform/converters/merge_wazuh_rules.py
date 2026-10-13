#!/usr/bin/env python3
"""Three-way merge: fresh converter output + hand-tuned live file.

Strategy:
- Rules are matched by a stable identity, not by position. The converter
  numbers rules by sorted Sigma filename, so its IDs shift whenever a file
  is added; the live file keeps the IDs it was deployed with. The identity
  is the converter's own mapping key, "<sigma file> :: <title>", recorded
  with its live rule ID in platform/converters/wazuh_rule_ids.json.
- Sigma rules already in the map: keep the LIVE version (hand-tuned wins).
- Sigma rules not in the map (new detections): take the fresh rule, give it
  the next free ID above every ID in use, record it in the map.
- Drift between a kept live rule and the Sigma-derived output is REPORTED
  (DRIFT lines, ::warning:: in CI) but never applied.
- Live rules with no Sigma source (hand-written tuning rules like
  100013/100020) or whose Sigma was deleted: kept as they are.
- The live file is edited as text: new rules are inserted before the
  closing </group>, so a run with nothing new leaves it byte-identical and
  "no changes" is a reliable signal.

Usage:
  python3 platform/converters/merge_wazuh_rules.py \
    --fresh /tmp/fresh_rules.xml \
    --live detections/wazuh/custom_rules.xml \
    --map platform/converters/wazuh_rule_ids.json \
    --output detections/wazuh/custom_rules.xml
"""
import argparse
import copy
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Wazuh reserves 100000-120000 for local rules.
CUSTOM_ID_MIN, CUSTOM_ID_MAX = 100000, 120000
# File names never contain " :: ", so the first one splits file from title;
# the title (group 3) may itself contain " :: ".
MAPPING_LINE = re.compile(r"^\s*(\d+) <-> (.+?) :: (.*?)\s*$")
# Elements that point at other rule IDs and must follow a renumbering.
ID_REFERENCES = ("if_sid", "if_matched_sid")
# Elements ignored by the drift report: they do not change what matches.
COSMETIC = ("description", "group")


def strip_comments(text):
    # Parse without comments: the converter's header comments are not
    # guaranteed to be valid XML, and comments carry no rule logic.
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def parse_rules(text):
    root = ET.fromstring(strip_comments(text))
    rules = [r for r in root.iter("rule") if r.get("id")]
    return root, rules


def decode_key_part(text):
    """Inverse of sigma_to_wazuh.encode_key_part (comments cannot hold "--")."""
    return re.sub(r"\\(\\|u002d)", lambda m: "\\" if m.group(1) == "\\" else "-", text)


def fresh_keys(text):
    """Converter header: '  100013 <-> file.yml :: Title' -> {id: key}."""
    keys = {}
    for line in text.splitlines():
        m = MAPPING_LINE.match(line)
        if m:
            keys[m.group(1)] = f"{decode_key_part(m.group(2))} :: {decode_key_part(m.group(3))}"
    return keys


def rule_signature(rule, renumber=None):
    """Behaviour-relevant content of a rule, for drift comparison only.
    Child order is irrelevant; IDs in if_sid/if_matched_sid are renumbered
    into the live numbering first."""
    renumber = renumber or {}
    sig = {"level": rule.get("level"), "frequency": rule.get("frequency"),
           "timeframe": rule.get("timeframe")}
    items = []
    for el in rule:
        if el.tag in COSMETIC:
            continue
        text = " ".join((el.text or "").split())
        text = re.sub(r"\\([- ])", r"\1", text)             # converter escapes - and space
        text = re.sub(r"^(\(\?i\))\.\*|\.\*$", r"\1", text)  # redundant .* around substring patterns
        if el.tag in ID_REFERENCES:
            text = ",".join(sorted(renumber.get(t.strip(), t.strip()) for t in text.split(",") if t.strip()))
        if el.tag == "mitre":
            text = ",".join(sorted(i.text or "" for i in el.iter("id")))
        if el.tag in ("group", "if_group"):
            text = ",".join(sorted(t for t in text.split(",") if t))
        attrs = ",".join(f"{k}={v}" for k, v in sorted(el.attrib.items()))
        items.append(f"<{el.tag} {attrs}> {text}".replace(" >", ">"))
    sig["items"] = sorted(items)
    return sig


def drift(live_rule, fresh_rule, renumber):
    """Human-readable differences (empty when equivalent). Report only."""
    a, b = rule_signature(live_rule), rule_signature(fresh_rule, renumber)
    out = []
    for k in ("level", "frequency", "timeframe"):
        if a[k] != b[k]:
            out.append(f"{k}: live={a[k]} sigma={b[k]}")
    for item in sorted(set(a["items"]) - set(b["items"])):
        out.append(f"live only:  {item}")
    for item in sorted(set(b["items"]) - set(a["items"])):
        out.append(f"sigma only: {item}")
    return out


def render_rule(rule):
    rule = copy.deepcopy(rule)
    rule.tail = None
    ET.indent(rule, space="  ", level=1)
    return "  " + ET.tostring(rule, encoding="unicode").rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fresh", required=True)
    ap.add_argument("--live", required=True)
    ap.add_argument("--map", default="platform/converters/wazuh_rule_ids.json")
    ap.add_argument("--output", required=True)
    ap.add_argument("--fail-on-drift", action="store_true",
                    help="exit 2 when live rules differ from Sigma-derived output (default: report only)")
    args = ap.parse_args()

    map_path = Path(args.map)
    if not map_path.exists():
        sys.exit(f"ERROR: {map_path} not found; it maps each Sigma rule to its live Wazuh rule ID")
    try:
        fresh_text = Path(args.fresh).read_text()
        live_text = Path(args.live).read_text()
        id_map = json.loads(map_path.read_text())
        live_text, report = merge(fresh_text, live_text, id_map)
    except (ET.ParseError, json.JSONDecodeError, KeyError, OSError) as exc:
        sys.exit(f"ERROR: {type(exc).__name__}: {exc}")
    except MergeError as exc:
        sys.exit(f"ERROR: {exc}")

    Path(args.output).write_text(live_text)
    if report["added"]:
        map_path.write_text(json.dumps(id_map, indent=2) + "\n")
    print(f"Merged: kept {report['kept']} mapped live rules, {report['live_only']} live-only rules untouched, "
          f"added {len(report['added'])} new: {report['added']}")
    for note in report["skipped"]:
        print(f"NOTE: {note}")
    for rid, key, diffs in report["drift"]:
        print(f"DRIFT: live rule {rid} ({key}) differs from Sigma-derived output (report only, live kept):")
        for d in diffs:
            print(f"    {d}")
    if not report["drift"]:
        print("DRIFT: none")
    if report["drift"] and args.fail_on_drift:
        sys.exit(2)


class MergeError(Exception):
    pass


def merge(fresh_text, live_text, id_map):
    rule_ids = id_map["rules"]
    _, fresh_rules = parse_rules(fresh_text)
    _, live_rules = parse_rules(live_text)
    keys = fresh_keys(fresh_text)
    live_ids = {r.get("id") for r in live_rules}

    used = {int(i) for i in live_ids} | {int(i) for i in rule_ids.values()}
    next_id = max(used | {CUSTOM_ID_MIN}) + 1

    # fresh ID -> final ID, for every fresh rule (existing and new)
    renumber, new_rules, kept, skipped = {}, [], 0, []
    for rule in fresh_rules:
        fid = rule.get("id")
        key = keys.get(fid)
        if key is None:
            raise MergeError(f"fresh rule {fid} has no mapping line in the converter header")
        if key in rule_ids:
            renumber[fid] = str(rule_ids[key])
            if renumber[fid] in live_ids:
                kept += 1
            else:
                skipped.append(f"{key} (mapped to {renumber[fid]}, absent from live; not re-added)")
            continue
        if next_id > CUSTOM_ID_MAX:
            raise MergeError(f"no free rule ID left in {CUSTOM_ID_MIN}-{CUSTOM_ID_MAX}")
        renumber[fid] = str(next_id)
        rule_ids[key] = next_id
        new_rules.append(rule)
        next_id += 1

    added = []
    if new_rules:
        blocks = []
        for rule in new_rules:
            rule = copy.deepcopy(rule)
            rule.set("id", renumber[rule.get("id")])
            for el in rule.iter():
                if el.tag in ID_REFERENCES and el.text:
                    el.text = ", ".join(renumber.get(t.strip(), t.strip()) for t in el.text.split(","))
            blocks.append(render_rule(rule))
            added.append(f"{rule.get('id')} ({rule.findtext('description')})")
        close = live_text.rstrip().rfind("</group>")
        if close < 0:
            raise MergeError("live file has no closing </group>")
        live_text = live_text[:close].rstrip("\n") + "\n\n" + "\n".join(blocks) + "\n" + live_text[close:]

    # The merged file must still parse and keep every rule ID unique.
    _, merged = parse_rules(live_text)
    ids = [r.get("id") for r in merged]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise MergeError(f"duplicate rule IDs after merge: {dupes}")

    # Report (never apply) differences between the live rule and what the
    # current Sigma source would generate for it.
    live_by_id = {r.get("id"): r for r in live_rules}
    drifted = []
    for rule in fresh_rules:
        final = renumber[rule.get("id")]
        if rule in new_rules or final not in live_by_id:
            continue
        diffs = drift(live_by_id[final], rule, renumber)
        if diffs:
            drifted.append((final, keys[rule.get("id")], diffs))

    if new_rules:
        id_map["rules"] = dict(sorted(rule_ids.items()))
    report = {"kept": kept, "live_only": len(live_ids) - kept, "added": added,
              "skipped": skipped, "drift": sorted(drifted)}
    return live_text, report


if __name__ == "__main__":
    main()
