"""
forensic_analyzer.py - Python-based digital forensic analysis engine.

Implements rule-based detection of suspicious patterns across all evidence
categories. Findings are categorized as:
  - confirmed-evidence: Directly identified from data
  - ai-observation: Pattern-based inference (requires human verification)
  - possible-lead: Correlational suggestion for further investigation
"""

import re
from datetime import datetime, timezone
from typing import Any


# ─── SUSPICIOUS INDICATOR LISTS ───────────────────────────────────────────────

SUSPICIOUS_SMS_KEYWORDS = [
    "burn", "wipe", "delete the logs", "cold wallet", "btc", "bitcoin",
    "encrypted channel", "drop", "mixer", "sd card", "destroy", "untraceable",
    "dark web", "darknet", "tor", "anonymous", "shred", "sanitize", "clean the phone",
]

SUSPICIOUS_URL_PATTERNS = [
    ".onion", "darkforum", "mixer", "crypto-cashout", "anonymous",
    "vpn-bypass", "wipe-guide", "shredder", "bitcoin-tumbler", "launder",
    "coin-mixer", "darkmarket",
]

ANTI_FORENSIC_PACKAGES = [
    "org.torproject", "com.mywickr", "com.protectstar", "com.ishredder",
    "com.vaultapp", "org.briarproject", "com.silent", "com.ghostsecurity",
    "com.netshade", "com.tunnelbear", "com.nordvpn", "net.openvpn",
]

CRYPTO_KEYWORDS = ["btc", "bitcoin", "crypto", "wallet", "blockchain", "eth", "monero", "xmr"]

INTERNATIONAL_PREFIXES = ["+44", "+7", "+86", "+971", "+33", "+49", "+81", "+82"]


def _ts_hour(timestamp: str) -> int:
    """Extract UTC hour from an ISO timestamp."""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return 12


def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60}s"


# ─── ANALYSIS FUNCTIONS ───────────────────────────────────────────────────────

def analyze_sms(sms_records: list[dict]) -> dict:
    """Detect suspicious keywords in SMS messages."""
    flagged = []
    for msg in sms_records:
        body = (msg.get("body") or "").lower()
        matched = [kw for kw in SUSPICIOUS_SMS_KEYWORDS if kw in body]
        if matched:
            flagged.append({
                "record": msg,
                "matched_keywords": matched,
                "severity": "high" if len(matched) >= 2 else "medium",
            })

    # Detect crypto-related messages
    crypto_msgs = [
        m for m in sms_records
        if any(kw in (m.get("body") or "").lower() for kw in CRYPTO_KEYWORDS)
    ]

    # Detect international numbers not matching domestic pattern
    intl_msgs = [
        m for m in sms_records
        if any(str(m.get("number", "")).startswith(p) for p in INTERNATIONAL_PREFIXES)
    ]

    return {
        "category": "SMS Analysis",
        "total_records": len(sms_records),
        "suspicious_count": len(flagged),
        "flagged_messages": flagged,
        "crypto_related": len(crypto_msgs),
        "international_contacts": len(intl_msgs),
        "risk": "high" if len(flagged) >= 3 else "medium" if len(flagged) >= 1 else "low",
        "finding_type": "confirmed-evidence" if flagged else "possible-lead",
        "summary": (
            f"Found {len(flagged)} SMS messages with suspicious keywords out of {len(sms_records)} total. "
            f"{len(crypto_msgs)} crypto-related messages. {len(intl_msgs)} international number contacts."
        ),
    }


def analyze_call_patterns(call_records: list[dict]) -> dict:
    """Detect unusual calling patterns in call logs."""
    late_night = [c for c in call_records if _ts_hour(c.get("timestamp", "")) < 5 or _ts_hour(c.get("timestamp", "")) >= 22]
    very_short = [c for c in call_records if 0 < int(c.get("duration_sec") or 0) < 10]
    missed = [c for c in call_records if c.get("type") == "missed"]
    rejected = [c for c in call_records if c.get("type") == "rejected"]

    # Count calls per number
    number_freq: dict[str, int] = {}
    for c in call_records:
        num = c.get("number", "unknown")
        number_freq[num] = number_freq.get(num, 0) + 1
    repeated = {num: cnt for num, cnt in number_freq.items() if cnt >= 3}

    # International callers not in contacts
    intl_calls = [
        c for c in call_records
        if any(str(c.get("number", "")).startswith(p) for p in INTERNATIONAL_PREFIXES)
    ]

    suspicious = bool(late_night or very_short or repeated or intl_calls)
    return {
        "category": "Call Pattern Analysis",
        "total_records": len(call_records),
        "late_night_calls": [{"number": c.get("number"), "timestamp": c.get("timestamp"), "type": c.get("type")} for c in late_night],
        "very_short_calls": [{"number": c.get("number"), "duration": _fmt_duration(int(c.get("duration_sec") or 0))} for c in very_short],
        "missed_calls": len(missed),
        "rejected_calls": len(rejected),
        "repeated_numbers": repeated,
        "international_callers": len(intl_calls),
        "suspicious_count": len(late_night) + len(very_short) + len(intl_calls),
        "risk": "high" if (len(late_night) >= 2 and intl_calls) else "medium" if late_night or intl_calls else "low",
        "finding_type": "ai-observation" if suspicious else "possible-lead",
        "summary": (
            f"{len(late_night)} late-night calls (22:00–05:00 UTC), "
            f"{len(very_short)} suspiciously short calls, "
            f"{len(intl_calls)} international calls, "
            f"{len(repeated)} numbers called 3+ times."
        ),
    }


def analyze_browser_history(browser_records: list[dict]) -> dict:
    """Detect suspicious websites in browser history."""
    flagged = []
    for record in browser_records:
        url = (record.get("url") or "").lower()
        title = (record.get("title") or "").lower()
        matched = [p for p in SUSPICIOUS_URL_PATTERNS if p in url or p in title]
        if matched:
            flagged.append({
                "record": record,
                "matched_patterns": matched,
                "severity": "high" if ".onion" in url else "medium",
            })

    # High visit count suspicious sites
    high_visit_suspicious = [
        r for r in flagged if int(r["record"].get("visits") or 0) >= 5
    ]

    return {
        "category": "Browser History Analysis",
        "total_records": len(browser_records),
        "suspicious_count": len(flagged),
        "flagged_urls": flagged,
        "high_visit_suspicious": len(high_visit_suspicious),
        "darknet_access": any(".onion" in (r["record"].get("url") or "") for r in flagged),
        "risk": "high" if any(".onion" in (r["record"].get("url") or "") for r in flagged) else "medium" if flagged else "low",
        "finding_type": "confirmed-evidence" if flagged else "possible-lead",
        "summary": (
            f"Found {len(flagged)} suspicious URLs out of {len(browser_records)} total. "
            f"{'Darknet (.onion) access detected. ' if any('.onion' in (r['record'].get('url') or '') for r in flagged) else ''}"
            f"{len(high_visit_suspicious)} suspicious sites with high visit counts."
        ),
    }


def analyze_gps_activity(gps_records: list[dict]) -> dict:
    """Detect unusual GPS location patterns."""
    late_night_locs = [
        g for g in gps_records
        if _ts_hour(g.get("timestamp", "")) < 5 or _ts_hour(g.get("timestamp", "")) >= 23
    ]
    airport_locs = [
        g for g in gps_records
        if "airport" in (g.get("place") or "").lower() or "sfo" in (g.get("place") or "").lower()
    ]

    # Detect rapid location changes (>50 km in short time)
    rapid_moves = []
    sorted_gps = sorted(gps_records, key=lambda g: g.get("timestamp", ""))
    for i in range(1, len(sorted_gps)):
        g1, g2 = sorted_gps[i-1], sorted_gps[i]
        lat1, lng1 = g1.get("latitude", 0) or 0, g1.get("longitude", 0) or 0
        lat2, lng2 = g2.get("latitude", 0) or 0, g2.get("longitude", 0) or 0
        # Rough km estimate (1 deg lat ≈ 111 km)
        dist_km = ((lat2 - lat1)**2 + (lng2 - lng1)**2) ** 0.5 * 111
        if dist_km > 20:
            rapid_moves.append({"from": g1.get("place"), "to": g2.get("place"), "distance_km": round(dist_km, 1)})

    return {
        "category": "GPS Activity Analysis",
        "total_records": len(gps_records),
        "late_night_locations": [{"place": g.get("place"), "timestamp": g.get("timestamp")} for g in late_night_locs],
        "airport_visits": [{"place": g.get("place"), "timestamp": g.get("timestamp")} for g in airport_locs],
        "rapid_movements": rapid_moves,
        "suspicious_count": len(late_night_locs) + len(airport_locs),
        "risk": "high" if airport_locs and late_night_locs else "medium" if late_night_locs else "low",
        "finding_type": "ai-observation",
        "summary": (
            f"{len(late_night_locs)} late-night GPS records, "
            f"{len(airport_locs)} airport location(s), "
            f"{len(rapid_moves)} rapid movement events."
        ),
    }


def analyze_apps(app_records: list[dict]) -> dict:
    """Identify suspicious and anti-forensic applications."""
    suspicious_apps = [a for a in app_records if a.get("suspicious")]
    anti_forensic = [
        a for a in app_records
        if any(p in (a.get("package") or "") for p in ANTI_FORENSIC_PACKAGES)
    ]
    crypto_apps = [
        a for a in app_records
        if any(kw in (a.get("name") or "").lower() for kw in ["wallet", "crypto", "bitcoin", "exodus", "coinbase"])
    ]
    high_permission = [
        a for a in app_records
        if len(a.get("permissions") or []) >= 4
    ]

    return {
        "category": "Application Analysis",
        "total_records": len(app_records),
        "suspicious_apps": [{"name": a.get("name"), "package": a.get("package"), "category": a.get("category")} for a in suspicious_apps],
        "anti_forensic_apps": [{"name": a.get("name"), "package": a.get("package")} for a in anti_forensic],
        "crypto_apps": [{"name": a.get("name"), "package": a.get("package")} for a in crypto_apps],
        "high_permission_apps": len(high_permission),
        "suspicious_count": len(suspicious_apps),
        "risk": "high" if len(suspicious_apps) >= 3 else "medium" if suspicious_apps else "low",
        "finding_type": "confirmed-evidence" if suspicious_apps else "possible-lead",
        "summary": (
            f"{len(suspicious_apps)} suspicious apps, {len(anti_forensic)} anti-forensic tools, "
            f"{len(crypto_apps)} crypto wallet apps, {len(high_permission)} apps with 4+ permissions."
        ),
    }


def analyze_contacts(contact_records: list[dict], sms_records: list[dict], call_records: list[dict]) -> dict:
    """Find unknown numbers appearing in communications not saved in contacts."""
    saved_numbers = {c.get("number", "") for c in contact_records}
    all_comm_numbers = set()
    for r in sms_records + call_records:
        num = r.get("number", "")
        if num:
            all_comm_numbers.add(num)

    unknown_numbers = all_comm_numbers - saved_numbers
    intl_unknown = [n for n in unknown_numbers if any(n.startswith(p) for p in INTERNATIONAL_PREFIXES)]

    return {
        "category": "Contact Analysis",
        "total_contacts": len(contact_records),
        "total_comm_numbers": len(all_comm_numbers),
        "unknown_numbers": list(unknown_numbers),
        "international_unknown": intl_unknown,
        "suspicious_count": len(intl_unknown),
        "risk": "medium" if intl_unknown else "low",
        "finding_type": "ai-observation",
        "summary": (
            f"{len(unknown_numbers)} numbers communicating with device not in contacts list. "
            f"{len(intl_unknown)} are international numbers."
        ),
    }


def run_full_analysis(evidence: dict) -> dict:
    """Run all analysis functions and compile into a structured forensic report."""
    sms = evidence.get("sms", [])
    calls = evidence.get("calls", [])
    contacts = evidence.get("contacts", [])
    gps = evidence.get("gps", [])
    browser = evidence.get("browser", [])
    apps = evidence.get("apps", [])

    sms_analysis = analyze_sms(sms)
    call_analysis = analyze_call_patterns(calls)
    browser_analysis = analyze_browser_history(browser)
    gps_analysis = analyze_gps_activity(gps)
    app_analysis = analyze_apps(apps)
    contact_analysis = analyze_contacts(contacts, sms, calls)

    # Compute overall risk level
    risks = [
        sms_analysis["risk"], call_analysis["risk"],
        browser_analysis["risk"], gps_analysis["risk"], app_analysis["risk"],
    ]
    if risks.count("high") >= 3:
        overall_risk = "Critical"
    elif "high" in risks:
        overall_risk = "High"
    elif risks.count("medium") >= 2:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    # Build findings list
    findings = []
    for analysis in [sms_analysis, call_analysis, browser_analysis, gps_analysis, app_analysis, contact_analysis]:
        if analysis["suspicious_count"] > 0:
            findings.append({
                "category": analysis["category"],
                "title": analysis["summary"],
                "risk": analysis["risk"],
                "finding_type": analysis["finding_type"],
                "count": analysis["suspicious_count"],
            })

    total_suspicious = sum(a["suspicious_count"] for a in [
        sms_analysis, call_analysis, browser_analysis, gps_analysis, app_analysis, contact_analysis
    ])

    return {
        "overall_risk": overall_risk,
        "total_suspicious_items": total_suspicious,
        "findings": findings,
        "analyses": {
            "sms": sms_analysis,
            "calls": call_analysis,
            "browser": browser_analysis,
            "gps": gps_analysis,
            "apps": app_analysis,
            "contacts": contact_analysis,
        },
        "summary": (
            f"Forensic analysis of {len(sms)} SMS, {len(calls)} calls, {len(contacts)} contacts, "
            f"{len(gps)} GPS records, {len(browser)} browser entries, {len(apps)} apps. "
            f"Overall risk: {overall_risk}. Total suspicious indicators: {total_suspicious}."
        ),
        "recommendations": _generate_recommendations(overall_risk, findings),
    }


def _generate_recommendations(risk: str, findings: list) -> list[str]:
    recs = [
        "Preserve all collected evidence with strict chain of custody documentation",
        "Verify all SHA-256 hashes before submitting evidence for judicial review",
    ]
    if risk in ("Critical", "High"):
        recs += [
            "Immediately escalate to senior forensic examiner for review",
            "Cross-reference identified phone numbers with law enforcement databases",
            "Issue legal preservation orders for identified cloud accounts",
        ]
    if any("crypto" in f.get("category", "").lower() or "bitcoin" in f.get("title", "").lower() for f in findings):
        recs.append("Trace identified cryptocurrency wallet addresses via blockchain analysis")
    if any("airport" in f.get("title", "").lower() or "flight" in f.get("title", "").lower() for f in findings):
        recs.append("Coordinate with border control / airport authorities regarding flight risk")
    recs.append("Run AI-enhanced analysis with Ollama (llama3.2:3b) for deeper pattern correlation")
    return recs
