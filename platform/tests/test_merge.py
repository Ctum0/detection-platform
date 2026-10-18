import json
from pathlib import Path

import pytest

import merge_wazuh_rules as m
import sigma_to_wazuh as c

ROOT = Path(__file__).resolve().parents[2]


def fresh_xml(title="T :: with -- odd", level="10", pattern="(?i)a"):
    key_file, key_title = "x.yml", title
    return f"""<!--
  Rule ID <-> Sigma rule mapping:
    100001 <-> {c.encode_key_part(key_file)} :: {c.encode_key_part(key_title)}
-->
<group name="g,">
  <rule id="100001" level="{level}">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">{pattern}</field>
    <description>{title}</description>
  </rule>
</group>
"""


LIVE = """<group name="g,">
  <rule id="100050" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)a</field>
    <description>hand tuned</description>
  </rule>
  <rule id="100099" level="0"><if_sid>1</if_sid><description>suppress</description></rule>
</group>
"""


def test_key_with_separator_and_double_dash_matches_map():
    ids = {"rules": {"x.yml :: T :: with -- odd": 100050}}
    out, report = m.merge(fresh_xml(), LIVE, ids)
    assert out == LIVE                       # nothing new -> byte identical
    assert report["kept"] == 1 and report["added"] == [] and report["drift"] == []


def test_drift_is_reported_not_applied():
    ids = {"rules": {"x.yml :: T :: with -- odd": 100050}}
    out, report = m.merge(fresh_xml(level="12", pattern="(?i)b"), LIVE, ids)
    assert out == LIVE
    (rid, key, diffs), = report["drift"]
    assert rid == "100050" and any("level" in d for d in diffs)
    assert any("field" in d for d in diffs)


def test_new_rule_gets_next_free_id_and_is_recorded():
    ids = {"rules": {}}
    out, report = m.merge(fresh_xml(), LIVE, ids)
    assert ids["rules"]["x.yml :: T :: with -- odd"] == 100100
    assert 'id="100100"' in out and len(report["added"]) == 1
    m.parse_rules(out)  # still valid XML


def test_malformed_live_xml_is_clean_error(tmp_path):
    f, l, mp = tmp_path / "f.xml", tmp_path / "l.xml", tmp_path / "m.json"
    f.write_text(fresh_xml()); l.write_text("<group><rule id='1'></group>"); mp.write_text('{"rules": {}}')
    with pytest.raises(SystemExit) as exc:
        import sys
        sys.argv = ["m", "--fresh", str(f), "--live", str(l), "--map", str(mp), "--output", str(tmp_path / "o.xml")]
        m.main()
    assert "ParseError" in str(exc.value)


def test_missing_mapping_header_is_error():
    with pytest.raises(m.MergeError):
        m.merge("<group><rule id='100001' level='3'/></group>", LIVE, {"rules": {}})


def test_real_pipeline_keeps_live_file_stable(tmp_path):
    """Converter + merge against the repo files: every mapped Sigma rule
    resolves to a live ID (nothing mis-keyed), and new rules get added cleanly."""
    fresh = tmp_path / "fresh.xml"
    rules, mapping, skipped = c.convert(ROOT / "detections/sigma", 100001, "if_group")
    fresh.write_text(c.render(rules, mapping, skipped, 100001))
    ids = json.loads((ROOT / "platform/converters/wazuh_rule_ids.json").read_text())
    live = (ROOT / "detections/wazuh/custom_rules.xml").read_text()
    out, report = m.merge(fresh.read_text(), live, ids)
    assert report["skipped"] == []
    merged_rules = m.parse_rules(out)
    assert len(merged_rules) >= len(m.parse_rules(live))
