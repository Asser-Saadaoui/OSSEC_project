import speakeasy
import yara
import json
import sys
import os
import argparse


def analyze_and_scan(exe_path, yara_rule_path):
    print(f"[*] Compiling YARA rules from: {yara_rule_path}")
    try:
        rules = yara.compile(filepath=yara_rule_path)
    except yara.SyntaxError as e:
        print(f"[!] YARA Syntax Error: {e}")
        sys.exit(1)

    print(f"[*] Initializing Speakeasy for: {exe_path}")
    se = speakeasy.Speakeasy()

    # On Windows, make sure the file handle is fully released before loading.
    # If exe_path came from a NamedTemporaryFile, close it first outside this function.
    try:
        module = se.load_module(exe_path)
    except Exception as e:
        print(f"[!] Failed to load module: {e}")
        print("[!] Tip: If you see [Errno 22], ensure no other handle is open on this file.")
        sys.exit(1)

    print("[*] Starting emulation... (this may take a few moments)")
    try:
        se.run_module(module)
    except Exception as e:
        # Don't exit — we still scan whatever was captured before the crash
        print(f"[!] Emulation stopped/crashed: {e}")
        print("[*] Continuing with partial report...")

    report = se.get_report()
    triggered_rules = set()

    print("\n--- YARA SCAN RESULTS ---")

    # 1. Scan the emulated memory dumps
    #    Malware often unpacks itself in memory — we scan those dumped chunks.
    for entry in report.get('entry_points', []):
        for mem_dump in entry.get('memory_dumps', []):
            buffer = mem_dump.get('data', b'')
            if buffer:
                matches = rules.match(data=buffer)
                for match in matches:
                    triggered_rules.add(match.rule)
                    print(f"[!] YARA MATCH (Memory): {match.rule} "
                          f"at address {hex(mem_dump.get('base', 0))}")

    # 2. Scan the behavioral JSON report
    #    Catches behavioral rules looking for API calls, C2 domains, registry keys, etc.
    report_string = json.dumps(report).encode('utf-8')
    behavior_matches = rules.match(data=report_string)
    for match in behavior_matches:
        triggered_rules.add(match.rule)
        print(f"[!] YARA MATCH (Behavioral Log): {match.rule}")

    if not triggered_rules:
        print("[*] No YARA matches found.")

    # 3. Final verdict
    print("\n--- FINAL VERDICT ---")
    if triggered_rules:
        print("[!] VERDICT: MALWARE DETECTED")
        print(f"[*] Triggered Signatures: {', '.join(triggered_rules)}")
    else:
        print("[*] VERDICT: CLEAN / UNDETECTED")

    return triggered_rules


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automated Speakeasy + YARA Malware Analyzer"
    )
    parser.add_argument(
        "target_exe",
        help="Path to the executable file you want to analyze"
    )
    parser.add_argument(
        "-y", "--yara-rules",
        default="my_rules.yar",
        help="Path to the YARA rules file (default: my_rules.yar)"
    )
    args = parser.parse_args()

    SAMPLE_EXE = args.target_exe
    YARA_RULES = args.yara_rules

    # Validate inputs before starting
    if not os.path.exists(SAMPLE_EXE):
        print(f"[!] Error: Target file not found: '{SAMPLE_EXE}'")
        sys.exit(1)

    if not os.path.exists(YARA_RULES):
        print(f"[!] Error: YARA rules file not found: '{YARA_RULES}'")
        sys.exit(1)

    analyze_and_scan(SAMPLE_EXE, YARA_RULES)