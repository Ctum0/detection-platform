"""Content checks: hand-tuned rule behaviour, Sigma metadata, pipeline file."""
import re
import uuid

import pytest
import yaml

from test_rules_xml import ROOT, load_rules, pcre2_patterns

SIGMA = ROOT / "detections" / "sigma"


def rule_by_id(rid):
    return next(r for r in load_rules() if r.get("id") == rid)


def test_100003_requires_exact_access_mask():
    rule = rule_by_id("100003")
    mask = next(p for t, n, p in pcre2_patterns(rule) if n == "win.eventdata.grantedAccess")
    rx = re.compile(mask)
    assert rx.search("0x1010") and rx.search("0x1fffff")
    assert not rx.search("0x101001")


def test_sigma_files_have_metadata_and_unique_uuid4():
    seen = {}
    for path in sorted(SIGMA.glob("*.yml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if not doc:
                continue
            for key in ("title", "id", "tags"):
                assert key in doc, f"{path.name}: missing {key}"
            sid = doc["id"]
            assert sid not in seen, f"{path.name}: duplicate id {sid} (also {seen[sid]})"
            seen[sid] = path.name
            if "correlation" in doc:
                continue
            u = uuid.UUID(str(sid))
            assert u.version == 4, f"{path.name}: id {sid} is not a UUID4"
            for key in ("author", "date", "references"):
                assert key in doc, f"{path.name}: missing {key}"


def test_linux_auth_pipeline_is_a_valid_pysigma_pipeline():
    pipeline = pytest.importorskip("sigma.processing.pipeline")
    p = pipeline.ProcessingPipeline.from_yaml((ROOT / "platform/pipelines/linux_auth.yml").read_text())
    assert p.name == "linux_auth" and p.priority == 20
