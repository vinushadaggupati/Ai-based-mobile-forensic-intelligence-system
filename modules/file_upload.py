"""
file_upload.py - Multi-file Upload Validation & Ingestion Helper
Handles Option B (Laptop Upload) and Option C (Mobile Exported Transfer).
"""

import os
from typing import List, Dict, Any
from modules.evidence_acquisition import register_uploaded_file

ALLOWED_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".sqlite", ".sqlite3",
    ".db", ".db3", ".log", ".zip", ".jpg", ".jpeg", ".png",
    ".mp4", ".m4a", ".pdf", ".raw", ".dd", ".img", ".e01"
}


def validate_file_extension(filename: str) -> bool:
    """Checks whether the file extension is forensic-supported."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def process_uploaded_files(
    uploaded_files,
    case_id: str,
    acquisition_method: str = "LAPTOP_UPLOAD",
    device_id: str = None
) -> List[Dict[str, Any]]:
    """
    Processes Streamlit UploadedFile objects, stores original evidence,
    calculates SHA-256 hash, and saves metadata in SQLite database.
    """
    saved_records = []
    for f in uploaded_files:
        if not validate_file_extension(f.name):
            continue
        
        file_bytes = f.getvalue()
        rec = register_uploaded_file(
            file_bytes=file_bytes,
            original_filename=f.name,
            case_id=case_id,
            acquisition_method=acquisition_method,
            device_id=device_id,
            original_source_path=f"upload://{f.name}",
        )
        saved_records.append(rec)
    return saved_records

