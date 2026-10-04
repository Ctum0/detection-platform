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
MAPPING_LINE = re.compile(r"^\s*(\d+) <-> (.+?) :: (.+?)\s*$")
# Elements that point at other rule IDs and must follow a renumbering.
ID_REFERENCES = ("if_sid", "if_matched_sid")


def strip_comments(text):
    # Parse without comments: the converter's header comments are not
    # guaranteed to be valid XML, and comments carry no rule logic.
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def parse_rules(text):
    root = ET.fromstring(strip_comments(text))
    rules = [r for r in root.iter("rule") if r.get("id")]
    return root, rules


def fresh_keys(text):
    """Converter header: '  100013 <-> file.yml :: Title' -> {id: key}."""
    keys = {}
    for line in text.splitlines():
        m = MAPPING_LINE.match(line)
        if m:
            keys[m.group(1)] = f"{m.group(2)} :: {m.group(3)}"
    return keys


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
    args = ap.parse_args()

    fresh_text = Path(args.fresh).read_text()
    live_text = Path(args.live).read_text()
    map_path = Path(args.map)
    if not map_path.exists():
        sys.exit(f"ERROR: {map_path} not found; it maps each Sigma rule to its live Wazuh rule ID")
    id_map = json.loads(map_path.read_text())
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
            sys.exit(f"ERROR: fresh rule {fid} has no mapping line in the converter header")
        if key in rule_ids:
            renumber[fid] = str(rule_ids[key])
            if renumber[fid] in live_ids:
                kept += 1
            else:
                skipped.append(f"{key} (mapped to {renumber[fid]}, absent from live; not re-added)")
            continue
        if next_id > CUSTOM_ID_MAX:
            sys.exit(f"ERROR: no free rule ID left in {CUSTOM_ID_MIN}-{CUSTOM_ID_MAX}")
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
            sys.exit("ERROR: live file has no closing </group>")
        live_text = live_text[:close].rstrip("\n") + "\n\n" + "\n".join(blocks) + "\n" + live_text[close:]

    # The merged file must still parse and keep every rule ID unique.
    _, merged = parse_rules(live_text)
    ids = [r.get("id") for r in merged]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        sys.exit(f"ERROR: duplicate rule IDs after merge: {dupes}")

    Path(args.output).write_text(live_text)
    if new_rules:
        id_map["rules"] = dict(sorted(rule_ids.items()))
        map_path.write_text(json.dumps(id_map, indent=2) + "\n")
    print(f"Merged: kept {kept} mapped live rules, {len(live_ids) - kept} live-only rules untouched, "
          f"added {len(added)} new: {added}")
    for s in skipped:
        print(f"NOTE: {s}")


if __name__ == "__main__":
    main()
