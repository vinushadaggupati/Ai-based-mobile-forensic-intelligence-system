"""
hash_manager.py - Dedicated SHA-256 Evidence Integrity Verification Module
Complies with NIST SP 800-101 and ISO/IEC 27037 forensic standards.
Uses Python hashlib to compute hashes from actual file binary streams.
"""

import hashlib
import os
import shutil
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone

CHUNK_SIZE = 65536  # 64 KB chunks for memory-efficient hashing of large files


def calculate_file_sha256(file_path: str) -> str:
    """
    Calculate the SHA-256 hash of a file by reading actual binary contents.
    Never uses hardcoded hashes. Handles files of any size.
    """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def calculate_bytes_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash from raw bytes in memory."""
    return hashlib.sha256(data).hexdigest()


def calculate_string_sha256(text: str) -> str:
    """Calculate SHA-256 hash from a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_file_integrity(original_hash: str, file_path: str) -> Tuple[str, Optional[str]]:
    """
    Recalculates the SHA-256 hash of the evidence file and compares with stored hash.
    
    Returns:
        (status, current_hash):
        - ("INTEGRITY VERIFIED", current_hash) if matches
        - ("INTEGRITY MISMATCH", current_hash) if different
        - ("VERIFICATION FAILED", None) if file missing or unreadable
    """
    if not file_path or not os.path.exists(file_path):
        return "VERIFICATION FAILED", None

    try:
        current_hash = calculate_file_sha256(file_path)
        if current_hash.lower() == original_hash.lower():
            return "INTEGRITY VERIFIED", current_hash
        else:
            return "INTEGRITY MISMATCH", current_hash
    except Exception as e:
        return "VERIFICATION FAILED", None


def create_working_copy(original_path: str, working_dir: str, evidence_id: str) -> str:
    """
    Creates an exact duplicate in working_copies/ directory for forensic examination.
    Forensic rule: Original evidence must never be modified or directly operated upon.
    """
    os.makedirs(working_dir, exist_ok=True)
    ext = os.path.splitext(original_path)[1]
    dest_filename = f"{evidence_id}_working{ext}"
    dest_path = os.path.join(working_dir, dest_filename)
    
    shutil.copy2(original_path, dest_path)
    return dest_path

