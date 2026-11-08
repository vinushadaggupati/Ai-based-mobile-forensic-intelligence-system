"""
log_analyzer.py - Forensic System and Diagnostic Log Analyzer
Examines Android logcat, crash traces, and text logs for root detection,
package installations, network routing changes, and anti-forensics.
"""

import re
from typing import Dict, Any, List

SUSPICIOUS_LOG_TERMS = [
    (r"(?i)\bsu\b|superuser|magisk|daemonsu", "Root / Privileged Escalation Activity", "HIGH"),
    (r"(?i)tor|orbot|127\.0\.0\.1:9050", "Tor Onion Routing Proxy Initialized", "HIGH"),
    (r"(?i)ishredder|wipe|shred|zerofill", "Secure Data Sanitization / Wiping Detected", "CRITICAL"),
    (r"(?i)failed password|unlock attempt failed", "Lockscreen Brute-force / Failed Authentication", "MEDIUM"),
    (r"(?i)usb debugging enabled|adbd", "ADB Debug Bridge State Change", "LOW"),
    (r"(?i)btc|bitcoin|coldcard|electrum|exodus", "Cryptocurrency Application Activity", "HIGH"),
    (r"(?i)mock location|allow_mock_location", "GPS Spoofing / Mock Location Active", "HIGH"),
]


def analyze_log_file(file_path: str, max_lines: int = 20000) -> Dict[str, Any]:
    """
    Scans system diagnostic logs using explainable forensic regex rules.
    """
    findings = []
    total_lines = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                total_lines += 1
                if total_lines > max_lines:
                    break

                for pattern, desc, severity in SUSPICIOUS_LOG_TERMS:
                    match = re.search(pattern, line)
                    if match:
                        findings.append({
                            "line_number": line_no,
                            "matched_term": match.group(0),
                            "description": desc,
                            "severity": severity,
                            "snippet": line.strip()[:160],
                        })
                        break  # Only one finding per line
    except Exception as e:
        return {"error": str(e), "total_lines": total_lines, "findings": []}

    return {
        "total_lines": total_lines,
        "suspicious_count": len(findings),
        "findings": findings,
    }

