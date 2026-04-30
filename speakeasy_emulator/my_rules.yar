rule Suspicious_Process_Injection {
    meta:
        description = "Detects Process Injection in Speakeasy Report"
    strings:
        $api1 = "VirtualAllocEx" ascii nocase
        $api2 = "WriteProcessMemory" ascii nocase
    condition:
        all of them
}