#!/usr/bin/env python3
"""Deterministic CI rule test harness using wazuh-logtest.

Runs committed sample events against a Wazuh manager container
and asserts each expected detection rule fires.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys


def find_default_container() -> str:
    # Check environment variable first
    if os.environ.get("WAZUH_CONTAINER"):
        return os.environ["WAZUH_CONTAINER"]
    
    # Check running docker containers
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}"], text=True
        )
        names = [line.strip() for line in out.splitlines() if line.strip()]
        for candidate in ["wazuh-test", "wazuh-spike", "single-node-wazuh.manager-1"]:
            if candidate in names:
                return candidate
    except Exception:
        pass
    return "wazuh-test"


def parse_fired_rule(logtest_output: str) -> str | None:
    """Extract fired rule ID from Phase 3 of wazuh-logtest output."""
    in_phase_3 = False
    for line in logtest_output.splitlines():
        if "**Phase 3:" in line:
            in_phase_3 = True
            continue
        if in_phase_3:
            # id: '100005'
            m = re.search(r"id:\s*['\"]?(\d+)['\"]?", line)
            if m:
                return m.group(1)
            # Or if another phase or alert begins
            if line.startswith("**Alert to be generated"):
                break
    return None


def run_tests(container: str, samples_dir: str) -> int:
    sample_files = sorted(glob.glob(os.path.join(samples_dir, "*.json")))
    if not sample_files:
        print(f"Error: No sample files found in {samples_dir}", file=sys.stderr)
        return 1

    print(f"=== Wazuh Rule Tests (Tier 1 Logtest) ===")
    print(f"Target container: {container}")
    print(f"Samples directory: {samples_dir} ({len(sample_files)} tests)")
    print("-" * 60)

    passed = 0
    failed = 0

    for sfile in sample_files:
        with open(sfile) as f:
            data = json.load(f)

        det_id = data.get("detection_id", os.path.basename(sfile).replace(".json", ""))
        name = data.get("name", det_id)
        expect_rule = str(data["expect_rule"])
        raw_event = data["event"]

        if isinstance(raw_event, dict):
            event_line = json.dumps(raw_event)
        else:
            event_line = str(raw_event).strip()

        # Run wazuh-logtest
        cmd = ["docker", "exec", "-i", container, "/var/ossec/bin/wazuh-logtest"]
        try:
            res = subprocess.run(
                cmd,
                input=event_line + "\n",
                text=True,
                capture_output=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            print(f"❌ [TIMEOUT] {det_id}: wazuh-logtest timed out")
            failed += 1
            continue
        except Exception as e:
            print(f"❌ [ERROR] {det_id}: execution error: {e}")
            failed += 1
            continue

        output = (res.stdout or "") + "\n" + (res.stderr or "")
        fired_rule = parse_fired_rule(output)

        if fired_rule == expect_rule:
            print(f"✅ [PASS] {det_id:8} ({name}): fired expected rule {expect_rule}")
            passed += 1
        else:
            print(
                f"❌ [FAIL] {det_id:8} ({name}): expected rule {expect_rule}, "
                f"but got {fired_rule or 'none'}"
            )
            # Show debug lines if failed
            for l in output.splitlines():
                if "**Phase" in l or "id:" in l or "description:" in l:
                    print(f"    | {l.strip()}")
            failed += 1

    print("-" * 60)
    print(f"Summary: {passed} passed, {failed} failed out of {len(sample_files)} total.")

    return 0 if failed == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Run wazuh-logtest deterministic tests")
    parser.add_argument(
        "--container",
        default=find_default_container(),
        help="Docker container name running wazuh-manager",
    )
    parser.add_argument(
        "--samples",
        default=os.path.join(os.path.dirname(__file__), "samples"),
        help="Path to directory containing sample json files",
    )
    args = parser.parse_args()

    sys.exit(run_tests(args.container, args.samples))


if __name__ == "__main__":
    main()
