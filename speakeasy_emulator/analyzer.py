import speakeasy
import yara
import json
import sys
import os

def analyze_and_scan(exe_path, yara_rule_path):
    print(f"[*] Compiling YARA rules from: {yara_rule_path}")
    try:
        rules = yara.compile(filepath=yara_rule_path)
    except yara.SyntaxError as e:
        print(f"[!] YARA Syntax Error: {e}")
        sys.exit(1)

    print(f"[*] Initializing Speakeasy for: {exe_path}")
    se = speakeasy.Speakeasy()

    try:
        # Load the executable into the emulator
        module = se.load_module(exe_path)
    except Exception as e:
        print(f"[!] Failed to load module: {e}")
        sys.exit(1)

    print("[*] Starting emulation... (this may take a few moments)")
    try:
        # Run the emulation
        se.run_module(module)
    except Exception as e:
        print(f"[!] Emulation stopped/crashed: {e}")
        # We don't exit here, because we still want to scan whatever it did before crashing

    # Get the detailed behavioral report from Speakeasy
    report = se.get_report()
    
    # We will keep a list of triggered YARA rules
    triggered_rules = set()

    print("\n--- YARA SCAN RESULTS ---")

    # 1. Scan the Emulated Memory Dumps
    # Malware often unpacks itself in memory. We scan the dumped memory chunks.
    # Note: Speakeasy might store memory data in the report under different keys depending on config.
    # Commonly, it tracks 'memory' or 'dropped_files'.
    for entry in report.get('entry_points', []):
        for mem_dump in entry.get('memory_dumps', []):
            buffer = mem_dump.get('data', b'')
            if buffer:
                matches = rules.match(data=buffer)
                for match in matches:
                    triggered_rules.add(match.rule)
                    print(f"[!] YARA MATCH (Memory): {match.rule} at address {hex(mem_dump.get('base', 0))}")

    # 2. Scan the Behavioral JSON Report
    # We convert the report to a string and scan it. This catches behavioral YARA rules 
    # looking for specific API calls, C2 domains, or registry keys that the malware tried to use.
    report_string = json.dumps(report).encode('utf-8')
    behavior_matches = rules.match(data=report_string)
    for match in behavior_matches:
        triggered_rules.add(match.rule)
        print(f"[!] YARA MATCH (Behavioral Log): {match.rule}")

    # 3. Final Verdict
    print("\n--- FINAL VERDICT ---")
    if triggered_rules:
        print("[!] VERDICT: MALWARE DETECTED")
        print(f"[*] Triggered Signatures: {', '.join(triggered_rules)}")
    else:
        print("[*] VERDICT: CLEAN / UNDETECTED")

import argparse # Make sure to add this at the top of your file!

# ... (keep your analyze_and_scan function exactly as it is) ...

if __name__ == "__main__":
    # Set up the command-line argument parser
    parser = argparse.ArgumentParser(description="Automated Speakeasy + YARA Malware Analyzer")
    
    # Require the user to provide the path to the EXE
    parser.add_argument("target_exe", help="Path to the executable file you want to analyze")
    
    # Make the YARA rules path optional (defaults to my_rules.yar if not provided)
    parser.add_argument("-y", "--yara-rules", default="my_rules.yar", help="Path to the YARA rules file (optional)")
    
    # Parse the arguments from the command line
    args = parser.parse_args()

    SAMPLE_EXE = args.target_exe
    YARA_RULES = args.yara_rules
    
    # Verify the files actually exist before starting
    if not os.path.exists(SAMPLE_EXE):
        print(f"[!] Error: The target file '{SAMPLE_EXE}' was not found.")
        sys.exit(1)
        
    if not os.path.exists(YARA_RULES):
        print(f"[!] Error: The YARA rules file '{YARA_RULES}' was not found.")
        sys.exit(1)

    # Run the pipeline
    analyze_and_scan(SAMPLE_EXE, YARA_RULES)