from collections import OrderedDict
from typing import Any, Dict, List
import json

try:
    import image_read as ir
    _to_safe = getattr(ir, '_make_json_serializable', None)
except Exception:
    ir = None
    _to_safe = None

PRIORITY_KEYS: List[str] = [
    "forensic",
    "markers",
    "duplicates",
    "unknown_ancillary_chunks",
    "chunk_counts",
    "chunks",
    "file",
    "file_size",
    "valid_signature",
    "iend_index",
    "trailing_bytes",
    "trailing_hexdump",
]

MARKER_PRIORITY: List[str] = [
    "IHDR", "iCCP", "pHYs", "tIME",
    "iTXt", "tEXt", "zTXt", "acTL", 
    "fcTL", "fdAT", "IEND"
]

def _make_safe(obj: Any) -> Any:
    if _to_safe is not None:
        try:
            safe = _to_safe(obj)
        except Exception:
            safe = obj
    else:
        safe = obj

    if isinstance(safe, (bytes, bytearray)):
        return {"type": "bytes", "length": len(safe)}
    if isinstance(safe, dict):
        safe.pop("payload", None)
        safe.pop("payload_head", None)
    return safe

def _sanitize_chunks(chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in chunks or []:
        entry = {}
        for k, v in c.items():
            entry[k] = _make_safe(v)
        out.append(entry)
    return out

def _order_markers(markers: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(markers, dict):
        return markers
    ordered = OrderedDict()
    for k in MARKER_PRIORITY:
        if k in markers:
            ordered[k] = _make_safe(markers[k])

    for k, v in markers.items():
        if k not in ordered:
            ordered[k] = _make_safe(v)
    return ordered

def _build_chunk_counts(chunks: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for c in chunks or []:
        t = c.get("type")
        if isinstance(t, str):
            counts[t] = counts.get(t, 0) + 1
    return counts

def _build_forensic(meta: Dict[str, Any]) -> Dict[str, Any]:
    chunks = meta.get("chunks") or []
    markers = meta.get("markers") or {}
    forensic: Dict[str, Any] = OrderedDict()

    crc_errors: List[Dict[str, Any]] = []
    reserved_violations: List[Dict[str, Any]] = []
    for c in chunks:
        if not c.get("crc_ok", True):
            crc_errors.append({"index": c.get("index"), "type": c.get("type")})
        if c.get("reserved_upper") is True:
            reserved_violations.append({"index": c.get("index"), "type": c.get("type")})

    if crc_errors:
        forensic["crc_errors"] = crc_errors
    if reserved_violations:
        forensic["reserved_bit_violations"] = reserved_violations

    trailing = meta.get("trailing_bytes", 0) or 0
    if trailing:
        forensic["trailing_after_IEND_bytes"] = trailing

    unknown_anc = meta.get("unknown_ancillary_chunks") or []
    if unknown_anc:
        forensic["unknown_ancillary_chunks"] = len(unknown_anc)

    def present(name: str) -> bool:
        m = markers.get(name) or {}
        return bool(m.get("present"))
    
    forensic["icc_profile_present"] = present("iCCP")
    forensic["pixel_density_present"] = present("pHYs")
    forensic["timestamp_present"] = present("tIME")
    forensic["text_chunks_present"] = any(present(n) for n in ["iTXt", "tEXt", "zTXt"])
    forensic["apng_present"] = any(present(n) for n in ["acTL", "fcTL", "fdAT"])

    forensic = OrderedDict((k, v) for k, v in forensic.items()
                         if not (isinstance(v, bool) and v is False) and not (isinstance(v, int) and v == 0))
    return forensic

def organize_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    out = OrderedDict()
    out['forensic'] = _build_forensic(meta)
    
    if "markers" in meta:
        out["markers"] = _order_markers(meta["markers"])

    if "duplicates" in meta:
        out["duplicates"] = _make_safe(meta["duplicates"])

    if "unknown_ancillary_chunks" in meta:
        out["unknown_ancillary_chunks"] = _make_safe(meta["unknown_ancillary_chunks"])

    if "chunks" in meta:
        out["chunk_counts"] = _build_chunk_counts(meta["chunks"])
        out["chunks"] = _sanitize_chunks(meta["chunks"])

    for k in ("file", "file_size", "valid_signature", "iend_index", "trailing_bytes", "trailing_hexdump"):
        if k in meta:
            out[k] = _make_safe(meta[k])

    for k, v in meta.items():
        if k in out:
            continue
        if k in PRIORITY_KEYS:
            continue
        out[k] = _make_safe(v)

    return out

def pretty_print_meta(meta: Dict[str, Any]) -> None:
    organized = organize_meta(meta)
    print(json.dumps(organized, indent=2, default=str))