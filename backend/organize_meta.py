from collections import OrderedDict
from typing import Any, Dict, List
import image_read as ir
import json

PRIORITY_KEYS: List[str] = [
    "forensic",
    "parsed_app2",
    "jpeg_app_segments",
    "jpeg_markers",
    "marker_counts",
    "exif",
    "info",
    "format",
    "mode",
    "size",
    "file",
    "trailing",
    "raw_header_hex",
    "icc_profile_present",
    "png_text",
]

def _sanitize_app_segments(app_segments: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for app_name, entries in (app_segments or {}).items():
        out[app_name] = []
        for e in entries:
            ee = {}
            for k, v in e.items():
                # always drop raw payloads / hex heads if present
                if k in ("payload", "payload_head"):
                    continue
                ee[k] = _make_safe(v)
            out[app_name].append(ee)
    return out

def _sanitize_markers(markers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for m in markers or []:
        entry = {}
        for k, v in m.items():
            # keep markers compact; remove any embedded raw bytes if present
            if k in ("payload", "payload_head"):
                continue
            entry[k] = _make_safe(v)
        out.append(entry)
    return out

def _make_safe(obj: Any) -> Any:
    # use image_read._make_json_serializable to handle bytes/tuples/etc.
    try:
        safe = ir._make_json_serializable(obj)
    except Exception:
        safe = obj
    # if still contains bytes (fallback), replace with size-only descriptor
    if isinstance(safe, (bytes, bytearray)):
        return {"type": "bytes", "length": len(safe)}
    # if dict, ensure nested payloads are removed
    if isinstance(safe, dict):
        # defensive removal
        safe.pop("payload", None)
        safe.pop("payload_head", None)
    return safe

def _order_forensic(forensic: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(forensic, dict):
        return forensic
    ordered = OrderedDict()
    for k in ("conflicts", "thumbnail", "maker_notes_present"):
        if k in forensic:
            ordered[k] = _make_safe(forensic[k])
    # then copy remaining keys in original order
    for k, v in forensic.items():
        if k not in ordered:
            ordered[k] = _make_safe(v)
    return ordered

def organize_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a new dict with keys ordered by forensic priority and with
    sensitive/raw fields sanitized for printing.
    """
    out = OrderedDict()
    # prioritized keys
    for key in PRIORITY_KEYS:
        if key in meta:
            if key == "jpeg_app_segments":
                out[key] = _sanitize_app_segments(meta[key])
            elif key == "jpeg_markers":
                out[key] = _sanitize_markers(meta[key])
            elif key == "forensic":
                out[key] = _order_forensic(meta[key])
            else:
                out[key] = _make_safe(meta[key])

    # append any remaining keys in original insertion order
    for k, v in meta.items():
        if k in out:
            continue
        out[k] = _make_safe(v)

    return out

def pretty_print_meta(meta: Dict[str, Any]) -> None:
    organized = organize_meta(meta)
    print(json.dumps(organized, indent=2, default=str))