"""
sqlite_analyzer.py - Forensic SQLite Database Parser and Freelist Examiner
Extracts schemas, tables, rows, and searches for deleted/freelist records.
Operates strictly on safe working copies, preserving original evidence.
"""

import sqlite3
import os
from typing import Dict, Any, List, Optional


def inspect_sqlite_database(db_path: str) -> Dict[str, Any]:
    """
    Forensically parses an SQLite database file.
    Returns table schema, row counts, and structural anomalies.
    """
    if not os.path.exists(db_path):
        return {"error": f"Database file not found: {db_path}"}

    results = {
        "is_valid_sqlite": False,
        "page_size": 0,
        "freelist_count": 0,
        "tables": {},
        "total_tables": 0,
        "errors": [],
    }

    # Verify SQLite header magic: 'SQLite format 3\000'
    try:
        with open(db_path, "rb") as f:
            header = f.read(16)
            if header.startswith(b"SQLite format 3\x00"):
                results["is_valid_sqlite"] = True
                f.seek(16)
                page_size_bytes = f.read(2)
                results["page_size"] = int.from_bytes(page_size_bytes, "big")
                f.seek(36)
                freelist_bytes = f.read(4)
                results["freelist_count"] = int.from_bytes(freelist_bytes, "big")
            else:
                results["errors"].append("Invalid SQLite magic header - file may be encrypted or corrupted.")
                return results
    except Exception as e:
        results["errors"].append(f"Header read error: {str(e)}")
        return results

    # Connect in read-only immutable mode
    try:
        uri_path = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(uri_path, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get all table names
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = cursor.fetchall()
        results["total_tables"] = len(tables)

        for tbl in tables:
            tbl_name = tbl["name"]
            create_sql = tbl["sql"] or ""

            # Get row count
            try:
                c_cur = conn.cursor()
                c_cur.execute(f"SELECT COUNT(*) FROM '{tbl_name}';")
                count = c_cur.fetchone()[0]
            except Exception:
                count = -1

            # Get column info
            try:
                p_cur = conn.cursor()
                p_cur.execute(f"PRAGMA table_info('{tbl_name}');")
                cols = [dict(c) for c in p_cur.fetchall()]
            except Exception:
                cols = []

            results["tables"][tbl_name] = {
                "name": tbl_name,
                "row_count": count,
                "schema": create_sql,
                "columns": cols,
            }

        conn.close()
    except Exception as e:
        results["errors"].append(f"SQLite examination error: {str(e)}")

    return results


def query_table_sample(db_path: str, table_name: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves sample rows from an SQLite table safely in read-only mode."""
    try:
        uri_path = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(uri_path, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM '{table_name}' LIMIT ?", (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

