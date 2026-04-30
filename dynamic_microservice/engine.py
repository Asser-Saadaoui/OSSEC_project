import re

WEIGHTS = {
    "office_spawns_shell": 80, "lolbas_execution": 60, "powershell_encoded": 70, 
    "powershell_download": 75, "exe_dropped": 40, "exe_dropped_temp": 60, 
    "script_dropped": 45, "startup_persistence": 70, "registry_run_key": 65, 
    "network_rare_port": 50, "process_injection": 85, "shadow_copy_deletion": 95, 
    "credential_dump": 90, "lateral_movement": 80, "ransomware_ext": 95
}

LOLBAS = ['certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'wmic.exe', 'bitsadmin.exe']
CRED_TOOLS = ['mimikatz', 'wce.exe', 'pwdump', 'lazagne']
RANSOMWARE_EXTS = ['.locked', '.crypto', '.enc', '.wnry', '.locky', '.zepto']
RARE_PORTS = ['4444', '1337', '31337', '8888', '9999']

def analyze_sysmon_logs(xml_file_path):
    indicators, rule_hits = [], {}
    threat_score = 0

    def add_hit(rule_key, severity, message):
        nonlocal threat_score
        count = rule_hits.get(rule_key, 0)
        if count < 3:
            threat_score += WEIGHTS.get(rule_key, 30) // (count + 1)
            rule_hits[rule_key] = count + 1
        indicators.append(f"[{severity}] {message}")

    try:
        with open(xml_file_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
        
        events = re.findall(r'<Event.*?</Event>', content, re.DOTALL | re.IGNORECASE)
    except Exception as e:
        return "ERROR", [f"File read error: {str(e)}"], 0

    for event in events:
        def get_val(name):
            match = re.search(fr'<Data Name=[\'"]{name}[\'"]>(.*?)</Data>', event, re.IGNORECASE)
            return match.group(1).lower() if match else ""

        eid_match = re.search(r'<EventID>(\d+)</EventID>', event, re.IGNORECASE)
        event_id = eid_match.group(1) if eid_match else "0"

        if event_id == "1":
            img, p_img, cmd = get_val('Image'), get_val('ParentImage'), get_val('CommandLine')
            
            if any(o in p_img for o in ['winword.exe', 'excel.exe']) and 'cmd.exe' in img:
                add_hit("office_spawns_shell", "Critical", f"Office spawned shell: {img}")
            if any(lb in img for lb in LOLBAS):
                add_hit("lolbas_execution", "High", f"LOLBAS executed: {img}")
            if 'powershell' in img and '-enc' in cmd:
                add_hit("powershell_encoded", "High", "Encoded PowerShell command run")
            if any(t in img or t in cmd for t in CRED_TOOLS):
                add_hit("credential_dump", "Critical", f"Credential dumper: {img}")
            if 'vssadmin' in img and 'delete' in cmd:
                add_hit("shadow_copy_deletion", "Critical", "Shadow copies deleted")

        elif event_id == "3":
            if get_val('DestinationPort') in RARE_PORTS:
                add_hit("network_rare_port", "Medium", f"Suspicious port used: {get_val('DestinationPort')}")

        elif event_id == "11":
            target = get_val('TargetFilename')
            if any(target.endswith(ext) for ext in RANSOMWARE_EXTS):
                add_hit("ransomware_ext", "Critical", f"Ransomware file: {target}")
            elif target.endswith('.exe'):
                add_hit("exe_dropped", "Suspicious", f"Executable dropped: {target}")

        elif event_id in ("12", "13"):
            if 'currentversion\\run' in get_val('TargetObject'):
                add_hit("registry_run_key", "High", "Startup registry key modified")

        elif event_id == "8":
            add_hit("process_injection", "Critical", "CreateRemoteThread API called")

    threat_score = min(threat_score, 100)
    verdict = "MALICIOUS" if threat_score >= 80 else "SUSPICIOUS" if threat_score >= 40 else "BENIGN"
    
    return verdict, list(set(indicators)), threat_score