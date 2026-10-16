"""Lint of the live detections/wazuh/custom_rules.xml (also run by convert-deploy).

These do not replace wazuh-logtest. They catch the mistakes that have bitten
this repo: invalid XML, duplicate IDs, comma lists in if_group, and regexes
that do not even compile.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "detections" / "wazuh" / "custom_rules.xml"


def load_rules():
    text = re.sub(r"<!--.*?-->", "", RULES.read_text(), flags=re.S)
    return list(ET.fromstring(text).iter("rule"))


def pcre2_patterns(rule):
    for el in rule.iter():
        if el.tag == "pcre2" or el.get("type") == "pcre2":
            yield el.tag, el.get("name"), (el.text or "")


def test_xml_parses_and_ids_unique_and_in_range():
    rules = load_rules()
    ids = [r.get("id") for r in rules]
    assert ids and all(i and i.isdigit() for i in ids)
    assert len(ids) == len(set(ids)), "duplicate rule IDs"
    assert all(100000 <= int(i) <= 120000 for i in ids)
    assert all(0 <= int(r.get("level")) <= 16 for r in rules)


def test_every_pcre2_pattern_compiles():
    count = 0
    for rule in load_rules():
        for tag, name, pattern in pcre2_patterns(rule):
            count += 1
            try:
                re.compile(pattern)
            except re.error as exc:
                pytest.fail(f"rule {rule.get('id')} {tag} {name}: {pattern!r}: {exc}")
    assert count > 0


def test_if_group_takes_a_single_group():
    for rule in load_rules():
        for el in rule.iter():
            if el.tag in ("if_group", "if_matched_group"):
                value = (el.text or "").strip()
                assert value and not re.search(r"[,\s]", value), (
                    f"rule {rule.get('id')}: {el.tag} takes one group name, got {value!r}")


def test_references_to_custom_rules_resolve():
    rules = load_rules()
    ids = {r.get("id") for r in rules}
    for rule in rules:
        for el in rule.iter():
            if el.tag in ("if_sid", "if_matched_sid"):
                for sid in re.split(r"[,\s]+", (el.text or "").strip()):
                    if sid.startswith("1") and len(sid) == 6:
                        assert sid in ids, f"rule {rule.get('id')} references unknown custom rule {sid}"
