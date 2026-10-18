import textwrap

import pytest
import yaml

import sigma_to_wazuh as c


def write(tmp_path, name, body):
    (tmp_path / name).write_text(textwrap.dedent(body))


def test_mitre_table_matches_notepad_tags():
    doc = yaml.safe_load((c.Path(__file__).resolve().parents[2] / "detections/sigma/notepad_execution.yml").read_text())
    tech = c.technique_of(doc)
    assert tech == "T1098"
    assert c.tactic_of(doc, tech) == c.MITRE[tech][0] == "Persistence"


def test_key_part_roundtrip_with_double_dash():
    import merge_wazuh_rules as m
    for text in ["plain", "a -- b", "x---y", "back\\slash", "trail-", "u\\u002d"]:
        enc = c.encode_key_part(text)
        assert "--" not in enc
        assert m.decode_key_part(enc) == text


def test_convert_basic_windows_rule(tmp_path):
    write(tmp_path, "a.yml", """
        title: Test Notepad
        id: 11111111-1111-4111-8111-111111111111
        tags: [attack.t1098, attack.persistence]
        logsource: {category: process_creation, product: windows}
        detection:
          selection: {Image|endswith: '\\x.exe'}
          condition: selection
        level: high
        """)
    rules, mapping, skipped = c.convert(tmp_path, 100001, "if_group")
    assert len(rules) == 1 and not skipped
    rule = rules[0][0]
    assert rule.get("level") == "10"
    assert rule.find("if_group").text == "sysmon_event1"
    assert rule.find("group") is None
    assert mapping == [(100001, "a.yml", "Test Notepad")]


def test_or_condition_is_skipped_not_mistranslated(tmp_path):
    write(tmp_path, "b.yml", """
        title: Or rule
        id: 22222222-2222-4222-8222-222222222222
        tags: [attack.t1059.001]
        logsource: {category: process_creation, product: windows}
        detection:
          a: {Image|endswith: '\\a.exe'}
          b: {Image|endswith: '\\b.exe'}
          condition: a or b
        """)
    rules, _, skipped = c.convert(tmp_path, 100001, "if_group")
    assert not rules and skipped and "or" in skipped[0][1]


def test_yaml_parse_error_is_clean(tmp_path):
    (tmp_path / "bad.yml").write_text("title: [unclosed\n  - x: : :\n")
    with pytest.raises(SystemExit) as exc:
        c.convert(tmp_path, 100001, "if_group")
    assert "bad.yml" in str(exc.value)


def test_render_never_emits_double_dash_in_comments(tmp_path):
    write(tmp_path, "c.yml", """
        title: 'Odd -- title :: with separator'
        id: 33333333-3333-4333-8333-333333333333
        tags: [attack.t1098]
        logsource: {category: process_creation, product: windows}
        detection:
          s: {Image|endswith: '\\n.exe'}
          condition: s
        """)
    rules, mapping, skipped = c.convert(tmp_path, 100001, "if_group")
    xml = c.render(rules, mapping, skipped, 100001)
    import xml.etree.ElementTree as ET, re
    ET.fromstring(xml)  # comments are legal, so the file parses
    body = re.findall(r"<!--(.*?)-->", xml, flags=re.S)
    assert all("--" not in b for b in body)


def test_real_sigma_dir_converts():
    root = c.Path(__file__).resolve().parents[2]
    rules, mapping, skipped = c.convert(root / "detections/sigma", 100001, "if_group")
    assert len(rules) == 11
    assert skipped == []
