"""Comprehensive test suite for Multi-SIEM Schema Normalization and Field Mapping.

Validates that vendor-agnostic Sigma rules are accurately normalized across:
1. Splunk Common Information Model (CIM)
2. Microsoft Sentinel ASIM (Advanced Security Information Model)
3. Microsoft Defender for Endpoint (MDE / Advanced Hunting)
4. CrowdStrike Falcon LogScale (CQL)
5. Wazuh SIEM XML
"""

import sys
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "operator-console"))

from app.converter import (
    translate_sigma_rule,
    SCHEMA_FIELD_MAPPINGS,
    SCHEMA_METADATA,
    PRESET_RULES,
)


def test_schema_metadata_structure():
    """Verify all 6 supported schema profiles have documentation and target sources."""
    expected_schemas = [
        "raw_sysmon",
        "splunk_cim",
        "sentinel_asim",
        "sentinel_mde",
        "crowdstrike_cql",
        "wazuh_xml",
    ]
    for s in expected_schemas:
        assert s in SCHEMA_METADATA
        assert "name" in SCHEMA_METADATA[s]
        assert "description" in SCHEMA_METADATA[s]
        assert "target_source" in SCHEMA_METADATA[s]


def test_core_fields_have_mappings_for_all_schemas():
    """Verify core EDR/SIEM fields are mapped across all 6 schema profiles."""
    core_fields = ["Image", "CommandLine", "ParentImage", "TargetObject", "GrantedAccess", "EventID"]
    for f in core_fields:
        assert f in SCHEMA_FIELD_MAPPINGS
        mapping = SCHEMA_FIELD_MAPPINGS[f]
        assert "raw_sysmon" in mapping
        assert "splunk_cim" in mapping
        assert "sentinel_asim" in mapping
        assert "sentinel_mde" in mapping
        assert "crowdstrike_cql" in mapping
        assert "wazuh_xml" in mapping


def test_powershell_preset_generates_all_normalized_dialects():
    """Verify PowerShell download cradle rule transpiles into all normalized schemas."""
    preset_yaml = PRESET_RULES["t1059-001"]["yaml"]
    res = translate_sigma_rule(preset_yaml)
    assert res["valid"] is True
    queries = res["queries"]

    # 1. Wazuh XML
    assert "wazuh" in queries
    assert "<rule" in queries["wazuh"]
    assert "win.eventdata.commandLine" in queries["wazuh"]

    # 2. Splunk CIM
    assert "splunk_cim" in queries
    assert "| from datamodel:Endpoint.Processes" in queries["splunk_cim"]
    assert 'process_name="*powershell.exe"' in queries["splunk_cim"]
    assert 'process="*DownloadString*"' in queries["splunk_cim"]

    # 3. Sentinel ASIM
    assert "sentinel_asim" in queries
    assert "TargetProcessName" in queries["sentinel_asim"] or "TargetProcessCommandLine" in queries["sentinel_asim"]

    # 4. Sentinel MDE
    assert "sentinel_mde" in queries
    assert "DeviceProcessEvents" in queries["sentinel_mde"]
    assert "FileName" in queries["sentinel_mde"]
    assert "ProcessCommandLine" in queries["sentinel_mde"]

    # 5. CrowdStrike CQL
    assert "cql" in queries
    assert "#event_simpleName=/ProcessRollup2/" in queries["cql"]
    assert "ImageFileName" in queries["cql"]
    assert "CommandLine" in queries["cql"]

    # Schema mapping matrix
    assert "schema_mappings" in res
    assert "CommandLine" in res["schema_mappings"]["detected_fields"]
    assert "Image" in res["schema_mappings"]["detected_fields"]


def test_registry_preset_routes_to_registry_datamodels():
    """Verify registry rules correctly route to Endpoint.Registry and DeviceRegistryEvents."""
    preset_yaml = PRESET_RULES["t1547-001"]["yaml"]
    res = translate_sigma_rule(preset_yaml)
    assert res["valid"] is True
    queries = res["queries"]

    # Splunk CIM should target Endpoint.Registry
    assert "| from datamodel:Endpoint.Registry" in queries["splunk_cim"]
    assert "registry_key_name" in queries["splunk_cim"]

    # Sentinel MDE should target DeviceRegistryEvents
    assert "DeviceRegistryEvents" in queries["sentinel_mde"]
    assert "RegistryKey" in queries["sentinel_mde"]

    # CrowdStrike CQL should target RegistryEvent
    assert "#event_simpleName=/RegistryEvent/" in queries["cql"]
    assert "RegKeyName" in queries["cql"]


def test_edge_case_empty_yaml():
    """Edge Case: Empty YAML input should fail cleanly without exceptions."""
    res = translate_sigma_rule("")
    assert res["valid"] is False
    assert "empty" in res["error"].lower()

    res_whitespace = translate_sigma_rule("   \n\t  ")
    assert res_whitespace["valid"] is False


def test_edge_case_malformed_yaml():
    """Edge Case: Malformed YAML syntax should return valid: False with error string."""
    bad_yaml = "title: Broken\nlogsource:\n  - incomplete: [["
    res = translate_sigma_rule(bad_yaml)
    assert res["valid"] is False
    assert "failed" in res["error"].lower() or "yaml" in res["error"].lower()


def test_edge_case_unknown_custom_fields():
    """Edge Case: Custom fields not in mapping matrix should gracefully pass through."""
    custom_yaml = """
title: Custom Field Rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    UnknownProprietaryField: 'SuspiciousValue'
  condition: selection
"""
    res = translate_sigma_rule(custom_yaml)
    assert res["valid"] is True
    assert "UnknownProprietaryField" in res["schema_mappings"]["detected_fields"]
    # Fallback should map to the field itself rather than raising KeyError
    mapping = res["schema_mappings"]["mappings"]["UnknownProprietaryField"]
    assert mapping["raw_sysmon"] == "UnknownProprietaryField"
    assert mapping["splunk_cim"] == "UnknownProprietaryField"


def test_all_repo_sigma_rules_translate_cleanly():
    """Verify every single Sigma rule in the repository translates into valid queries."""
    import glob
    rule_files = glob.glob(str(ROOT / "detections/sigma/*.yml"))
    assert len(rule_files) >= 10

    for rfile in rule_files:
        content = Path(rfile).read_text(encoding="utf-8")
        res = translate_sigma_rule(content)
        assert res["valid"] is True, f"Failed translating {rfile}: {res.get('error')}"
        assert len(res["queries"]) >= 4, f"Missing backends for {rfile}"
        assert res["technique"].startswith("T")
