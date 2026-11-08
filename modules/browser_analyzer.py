"""
browser_analyzer.py - Android Chromium & Chrome Database Forensic Analyzer
Parses History databases for visited URLs, titles, visit counts, and darknet/mixer activities.
"""

import sqlite3
import os
from typing import List, Dict, Any
from datetime import datetime, timezone

SUSPICIOUS_URL_PATTERNS = [
    ".onion", "darkforum", "mixer", "tumbler", "crypto-cashout", "wipe-guide",
    "shredder", "xda-developers.com/wipe", "launder", "darkmarket", "torproject"
]


def analyze_chromium_history(db_path: str) -> Dict[str, Any]:
    """
    Parses Android Chrome History database.
    Extracts URLs, titles, visit counts, and checks for suspicious keywords.
    """
    if not os.path.exists(db_path):
        return {"error": "File not found", "records": [], "suspicious": []}

    results = {
        "total_urls": 0,
        "suspicious_count": 0,
        "records": [],
        "suspicious": [],
    }

    try:
        uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if 'urls' table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls';")
        if not cursor.fetchone():
            conn.close()
            return {"error": "Not a standard Chromium History database ('urls' table missing)", "records": [], "suspicious": []}

        cursor.execute("""
            SELECT id, url, title, visit_count, typed_count, last_visit_time, hidden
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 500;
        """)

        rows = cursor.fetchall()
        results["total_urls"] = len(rows)

        for row in rows:
            url_str = (row["url"] or "").lower()
            title_str = (row["title"] or "").lower()

            # WebKit/Chromium timestamp conversion: microseconds since Jan 1, 1601 UTC
            raw_time = row["last_visit_time"]
            time_str = "Unknown"
            if raw_time and raw_time > 0:
                try:
                    epoch_seconds = (raw_time - 11644473600000000) / 1000000
                    if 0 < epoch_seconds < 2500000000:
                        time_str = datetime.fromtimestamp(epoch_seconds, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    pass

            item = {
                "id": row["id"],
                "url": row["url"],
                "title": row["title"] or "Untitled",
                "visit_count": row["visit_count"],
                "timestamp": time_str,
            }
            results["records"].append(item)

            # Check suspicious indicators
            matched = [p for p in SUSPICIOUS_URL_PATTERNS if p in url_str or p in title_str]
            if matched:
                item["matched_patterns"] = matched
                item["severity"] = "HIGH" if ".onion" in url_str else "MEDIUM"
                results["suspicious"].append(item)

        results["suspicious_count"] = len(results["suspicious"])
        conn.close()
    except Exception as e:
        results["error"] = str(e)

    return results

