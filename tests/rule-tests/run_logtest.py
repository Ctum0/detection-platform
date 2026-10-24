#!/usr/bin/env python3
"""Deterministic CI rule test harness using wazuh-logtest.

Performs paired regression testing:
1. Attack Events (True Positives): Asserts each attack event fires its expected detection rule.
2. Benign Events (True Negatives): Asserts legitimate administrative activity does NOT fire
   the detection rule (preventing false-positive alert fatigue in production).
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from typing import Optional, Tuple


def find_default_container() -> str:
    if os.environ.get("WAZUH_CONTAINER"):
        return os.environ["WAZUH_CONTAINER"]
    
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}"], text=True
        )
        names = [line.strip() for line in out.splitlines() if line.strip()]
        for candidate in ["wazuh-test", "wazuh-manager", "wazuh-spike", "single-node-wazuh.manager-1"]:
            if candidate in names:
                return candidate
    except Exception:
        pass
    return "wazuh-test"


def parse_fired_rule(logtest_output: str) -> Optional[str]:
    """Extract fired rule ID from Phase 3 of wazuh-logtest output."""
    in_phase_3 = False
    for line in logtest_output.splitlines():
        if "**Phase 3:" in line:
            in_phase_3 = True
            continue
        if in_phase_3:
            m = re.search(r"id:\s*['\"]?(\d+)['\"]?", line)
            if m:
                return m.group(1)
            if line.startswith("**Alert to be generated"):
                break
    return None


def execute_logtest(container: str, event_data: any, timeout_sec: int = 15) -> Tuple[Optional[str], str]:
    """Execute wazuh-logtest inside the container for a single event string or dict."""
    if isinstance(event_data, dict):
        event_line = json.dumps(event_data)
    else:
        event_line = str(event_data).strip()

    cmd = ["docker", "exec", "-i", container, "/var/ossec/bin/wazuh-logtest"]
    try:
        res = subprocess.run(
            cmd,
            input=event_line + "\n",
            text=True,
            capture_output=True,
            timeout=timeout_sec,
        )
        output = (res.stdout or "") + "\n" + (res.stderr or "")
        fired = parse_fired_rule(output)
        return fired, output
    except subprocess.TimeoutExpired:
        return None, "[TIMEOUT] wazuh-logtest timed out"
    except Exception as e:
        return None, f"[ERROR] execution error: {e}"


def run_tests(container: str, samples_dir: str, mode: str = "both", verbose: bool = False) -> int:
    sample_files = sorted(glob.glob(os.path.join(samples_dir, "*.json")))
    if not sample_files:
        print(f"Error: No sample files found in {samples_dir}", file=sys.stderr)
        return 1

    print(f"=== Wazuh Rule Tests: Paired True-Positive & Benign Regression Suite ===")
    print(f"Target container : {container}")
    print(f"Samples directory: {samples_dir} ({len(sample_files)} test fixtures)")
    print(f"Execution mode   : {mode.upper()}")
    print("=" * 72)

    total_attack_tests = 0
    attack_passed = 0
    attack_failed = 0

    total_benign_tests = 0
    benign_passed = 0
    benign_failed = 0

    for sfile in sample_files:
        with open(sfile, encoding="utf-8") as f:
            data = json.load(f)

        det_id = data.get("detection_id", os.path.basename(sfile).replace(".json", ""))
        name = data.get("name", det_id)
        expect_rule = str(data["expect_rule"])
        raw_event = data.get("event") or data.get("attack_event")
        benign_event = data.get("benign_event")
        benign_rationale = data.get("benign_rationale", "Normal administrative activity")

        print(f"\n▶ [{det_id}] {name} (Expect: Rule {expect_rule})")

        # -------------------------------------------------------------
        # 1. Attack Event (True Positive) Test
        # -------------------------------------------------------------
        if mode in ("both", "attack") and raw_event:
            total_attack_tests += 1
            fired_rule, output = execute_logtest(container, raw_event)
            if fired_rule == expect_rule:
                print(f"  [+] Attack Test (True Positive): PASSED (fired expected rule {expect_rule})")
                attack_passed += 1
            else:
                print(f"  [-] Attack Test (True Positive): FAILED! Expected {expect_rule}, got {fired_rule or 'none'}")
                if verbose or not fired_rule:
                    for l in output.splitlines():
                        if "**Phase" in l or "id:" in l or "description:" in l:
                            print(f"      | {l.strip()}")
                attack_failed += 1

        # -------------------------------------------------------------
        # 2. Benign Event (True Negative / Anti-Regression) Test
        # -------------------------------------------------------------
        if mode in ("both", "benign") and benign_event:
            total_benign_tests += 1
            fired_rule, output = execute_logtest(container, benign_event)
            
            # The benign event MUST NOT fire the high-severity detection rule
            if fired_rule != expect_rule:
                non_attack_desc = f"rule {fired_rule}" if fired_rule else "no alert (clean)"
                print(f"  [+] Benign Test (True Negative): PASSED ({non_attack_desc} -> rule {expect_rule} suppressed)")
                if verbose and fired_rule:
                    print(f"      (Benign event safely matched base/informational rule {fired_rule})")
                benign_passed += 1
            else:
                print(f"  [-] Benign Test (FALSE POSITIVE REGRESSION): FAILED!")
                print(f"      CRITICAL: Benign admin activity triggered alert rule {expect_rule}!")
                print(f"      Rationale: {benign_rationale}")
                for l in output.splitlines():
                    if "**Phase" in l or "id:" in l or "description:" in l:
                        print(f"      | {l.strip()}")
                benign_failed += 1
        elif mode in ("both", "benign") and not benign_event:
            print(f"  [!] Benign Test: SKIPPED (No benign fixture specified in {os.path.basename(sfile)})")

    print("\n" + "=" * 72)
    print("TEST EXECUTION SUMMARY:")
    if mode in ("both", "attack"):
        print(f"  • True Positives (Attack Detection): {attack_passed}/{total_attack_tests} passed ({attack_failed} failed)")
    if mode in ("both", "benign"):
        print(f"  • True Negatives (Benign Precision) : {benign_passed}/{total_benign_tests} passed ({benign_failed} false-positive regressions)")

    total_failures = attack_failed + benign_failed
    if total_failures == 0:
        print("\n🎉 ALL TESTS PASSED! True positive detection verified & zero false positives on benign activity.")
        return 0
    else:
        print(f"\n❌ REGRESSION FAILURE: {total_failures} test(s) failed.")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Deterministic Paired True-Positive & Benign Logtest Runner")
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
    parser.add_argument(
        "--mode",
        choices=["both", "attack", "benign"],
        default="both",
        help="Test execution mode: 'both', 'attack' (true positive only), or 'benign' (false positive regression only)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print verbose output from wazuh-logtest",
    )
    args = parser.parse_args()

    sys.exit(run_tests(args.container, args.samples, mode=args.mode, verbose=args.verbose))


if __name__ == "__main__":
    main()
