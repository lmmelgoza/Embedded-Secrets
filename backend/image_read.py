#!/usr/bin/env python3
import io
import json 
import hashlib
from typing import Any, Dict, Iterable, List
from PIL import Image, ExifTags
import xml.dom.minidom as minidom
try:
    import piexif
except Exception:
    piexif = None
try:
    from PIL import ImageCms
except Exception:
    ImageCms = None

def _exif_to_dict(exif) -> Dict[str, Any]:
    result = {}
    for tag_id, value in exif.items():
        tag = ExifTags.TAGS.get(tag_id, tag_id)
        if isinstance(value, bytes):
            try:
                value = value.decode(errors="replace")
            except Exception:
                value = repr(value)
        else:
            try:
                json.dumps({str(tag): value})
            except TypeError:
                value = str(value)
        result[tag] = value
    return result

def _make_json_serializable(obj):
    """Recursively convert bytes/bytearray to decoded strings and tuples to lists."""
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", "replace")
        except Exception:
            return repr(obj)
    if isinstance(obj, dict):
        return {str(k): _make_json_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_make_json_serializable(v) for v in obj]
    return obj

def _compute_hashes(data: bytes) -> Dict[str, Any]:
    """Return sha256 and md5 and size for given bytes."""
    h_sha256 = hashlib.sha256(data).hexdigest()
    h_md5 = hashlib.md5(data).hexdigest()
    return {"sha256": h_sha256, "md5": h_md5, "size": len(data)}

def _raw_header_bytes(data: bytes, n: int = 64) -> str:
    return data[:n].hex()

def _find_trailing_after_eoi(data: bytes) -> Dict[str, Any]:
    """Return bytes after EOI marker (0xFFD9) if any."""
    pos = data.rfind(b"\xFF\xD9")
    if pos == -1:
        return {"eoi_pos": None, "trailing_bytes": len(data)}
    trailing = len(data) - (pos + 2)
    return {"eoi_pos": pos, "trailing_bytes": trailing}

def _marker_name(byte_val: int) -> str:
    NAMES = {
        0xD8: "SOI", 0xD9: "EOI",
        0xDA: "SOS", 0xDB: "DQT", 0xC4: "DHT",
        0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2",
        0xC3: "SOF3", 0xC5: "SOF5", 0xC6: "SOF6", 0xC7: "SOF7",
        0xC9: "SOF9", 0xCA: "SOF10", 0xCB: "SOF11",
        0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xEB: "APP11", 0xED: "APP13",
        0xEE: "APP14", 0xFE: "COM", 0xDD: "DRI"
    }
    if 0xE0 <= byte_val <= 0xEF:
        return f"APP{byte_val - 0xE0}"
    return NAMES.get(byte_val, f"0xFF{byte_val:02X}")

def parse_jpeg_markers_full(data: bytes) -> List[Dict[str, Any]]:
    """
    Scan full JPEG markers and return ordered list of markers with offsets, lengths, and some parsed details:
    - SOF: height, width, precision, components, sampling factors
    - DQT: include hash of quant table bytes for fingerprinting
    - DHT/DQT/DRI presence and sizes
    - COM: text preview
    """
    markers = []
    L = len(data)
    if L < 2 or data[:2] != b'\xFF\xD8':
        return markers
    i = 2
    # record SOI
    markers.append({"name": "SOI", "marker": 0xD8, "offset": 0, "length": 2})
    while i < L:
        if data[i] != 0xFF:
            i = data.find(b"\xFF", i)
            if i == -1:
                break
        # skip fill 0xFF bytes
        j = i
        while j < L and data[j] == 0xFF:
            j += 1
        if j >= L:
            break
        marker = data[j]
        offset = j - 1
        j += 1
        # markers without length
        if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7):
            continue
        # stop scanning APP segments once we hit SOS (rest is compressed image data)
        if marker == 0xDA:
            break
        if j + 2 > L:
            break
        seg_len = int.from_bytes(data[j:j+2], "big")
        payload_len = max(seg_len - 2, 0)
        payload_start = j + 2
        payload_end = payload_start + payload_len
        if payload_end > L:
            payload_end = L
        payload = data[payload_start:payload_end]
        entry = {"name": _marker_name(marker), "marker": marker, "offset": offset, "length": 2 + seg_len, "payload_length": payload_len}
        # parse specifics
        try:
            if marker in (0xC0, 0xC1, 0xC2):  # SOF0/1/2
                # payload: precision (1), height (2), width (2), components (1), then per-component (3 bytes)
                if len(payload) >= 6:
                    precision = payload[0]
                    height = int.from_bytes(payload[1:3], "big")
                    width = int.from_bytes(payload[3:5], "big")
                    components = payload[5]
                    comps = []
                    idx = 6
                    for n in range(components):
                        if idx + 3 <= len(payload):
                            cid = payload[idx]
                            samp = payload[idx+1]
                            qtbl = payload[idx+2]
                            h = (samp >> 4) & 0xF
                            v = samp & 0xF
                            comps.append({"id": cid, "h": h, "v": v, "qt": qtbl})
                            idx += 3
                    entry["sof"] = {"precision": precision, "width": width, "height": height, "components": components, "component_info": comps}
            elif marker == 0xDB:  # DQT
                # store hash of the quant table payload for fingerprinting
                entry["dqt_md5"] = hashlib.md5(payload).hexdigest()
                entry["dqt_len"] = len(payload)
            elif marker == 0xC4:  # DHT
                entry["dht_len"] = len(payload)
                entry["dht_md5"] = hashlib.md5(payload).hexdigest()
            elif marker == 0xDD:  # DRI
                if len(payload) >= 2:
                    restart_interval = int.from_bytes(payload[:2], "big")
                    entry["restart_interval"] = restart_interval
            elif marker == 0xFE:  # COM
                try:
                    entry["comment_text"] = payload.decode("utf-8", "replace")
                except Exception:
                    entry["comment_preview"] = _bytes_to_printable(payload, 128)
            elif 0xE0 <= marker <= 0xEF:
                # APPn: keep small preview and common signatures
                try:
                    entry["payload_head_preview"] = _bytes_to_printable(payload[:128], 128)
                except Exception:
                    pass
                if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                    entry["app_type"] = "EXIF"
                if marker == 0xE1 and (b"<x:xmpmeta" in payload or b"http://ns.adobe.com/xap/1.0/" in payload):
                    entry["app_type"] = entry.get("app_type", "") + " XMP"
                if marker == 0xE2 and payload.startswith(b"MPF"):
                    entry["app_type"] = "MPF"
                if marker == 0xED and payload.startswith(b"Photoshop 3.0"):
                    entry["app_type"] = "Photoshop-IRB"
                if marker == 0xEB and (b"JUMBF" in payload or b"c2pa" in payload.lower()):
                    entry["app_type"] = "JUMBF/C2PA"
        except Exception:
            pass
        markers.append(entry)
        i = payload_end
    return markers

def parse_jpeg_app_segments(data: bytes, wanted=(1,2,11,13), keep_payload: bool = False):
    """
    Return dict of APP segments requested (keys like 'APP1', 'APP2', ...).
    Each entry is a list of dicts: {offset, length, payload_length, payload_head (hex)}
    If keep_payload is True the full payload bytes are included under 'payload' (caller should remove before serializing).
    """
    res = {}
    L = len(data)
    if L < 2 or data[0:2] != b"\xFF\xD8":
        return res
    i = 2
    while i < L:
        # find next 0xFF
        if data[i] != 0xFF:
            i = data.find(b"\xFF", i)
            if i == -1:
                break
        # skip fill bytes 0xFF
        j = i
        while j < L and data[j] == 0xFF:
            j += 1
        if j >= L:
            break
        marker = data[j]
        i = j + 1
        # markers without length
        if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7):
            continue
        # stop scanning APP segments once we hit SOS (rest is compressed image data)
        if marker == 0xDA:
            break
        if i + 2 > L:
            break
        seg_len = int.from_bytes(data[i:i+2], "big")
        payload_len = max(seg_len - 2, 0)
        payload_start = i + 2
        payload_end = payload_start + payload_len
        if payload_end > L:
            payload_end = L
        payload = data[payload_start:payload_end]
        if 0xE0 <= marker <= 0xEF:
            app_num = marker - 0xE0
            if app_num in wanted:
                name = f"APP{app_num}"
                entry = {
                    "offset": j-1,
                    "length": 2 + seg_len,
                    "payload_length": payload_len,
                    "payload_head": payload[:256].hex()
                }
                if keep_payload:
                    entry["payload"] = payload  # caller must remove before JSON serialization
                # best-effort classification / decode for common blocks
                try: entry["payload_head_parsed"] = _try_decode_app_payload(entry["payload_head"], app_num)
                except Exception:
                    pass
                try:
                    if app_num == 1:
                        if payload.startswith(b"Exif\x00\x00"):
                            entry["type"] = "EXIF"
                        elif b"<x:xmpmeta" in payload or b"http://ns.adobe.com/xap/1.0/" in payload:
                            entry["type"] = "XMP"
                            try:
                                entry["payload_text"] = payload.decode("utf-8", "replace")
                            except Exception:
                                pass
                        else:
                            entry["type"] = "APP1"
                    elif app_num == 2 and payload[:3] == b"MPF":
                        entry["type"] = "MPF"
                    elif app_num == 13 and payload.startswith(b"Photoshop 3.0"):
                        entry["type"] = "Photoshop-IRB"
                    elif app_num == 11 and b"JUMBF" in payload:
                        entry["type"] = "JUMBF"
                    else:
                        entry["type"] = f"APP{app_num}"
                except Exception:
                    pass
                res.setdefault(name, []).append(entry)
        i = payload_end
    return res

def _bytes_to_printable(b: bytes, maxlen: int = 512) -> str:
    # show readable ASCII runs, otherwise dot for non-printable
    s = []
    for ch in b[:maxlen]:
        if 32 <= ch < 127:
            s.append(chr(ch))
        else:
            s.append(".")
    return "".join(s)

def _try_decode_app_payload(payload_hex: str, app_num: int):
    """
    Best-effort decoding of an APP segment head (hex string).
    Returns a dict with optional keys: payload_bytes_len, ascii_preview, type_hint, payload_text, exif_tags, icc_description
    (kept for backward compatibility; full parsing for APP1/APP2 is done in read_image_from_bytes when keep_payload=True)
    """
    out = {}
    try:
        payload = bytes.fromhex(payload_hex)
    except Exception:
        return out
    out["payload_bytes_len"] = len(payload)
    out["ascii_preview"] = _bytes_to_printable(payload, maxlen=256)

    # APP1: EXIF or XMP
    if app_num == 1:
        if payload.startswith(b"Exif\x00\x00"):
            out["type_hint"] = "EXIF"
        if b"<x:xmpmeta" in payload or b"http://ns.adobe.com/xap/1.0/" in payload:
            out["type_hint"] = "XMP"
            try:
                txt = payload.decode("utf-8", "replace")
                try:
                    dom = minidom.parseString(txt)
                    out["payload_text"] = dom.toprettyxml(indent="  ")
                except Exception:
                    out["payload_text"] = txt
            except Exception:
                out["payload_text_error"] = "decode failed"
    # APP2: often ICC_PROFILE or MPF
    if app_num == 2:
        if payload.startswith(b"ICC_PROFILE"):
            out["type_hint"] = "ICC_PROFILE"
        elif payload.startswith(b"MPF"):
            out["type_hint"] = "MPF"
    if app_num == 11 and b"JUMBF" in payload:
        out["type_hint"] = "JUMBF"
    if app_num == 13 and payload.startswith(b"Photoshop 3.0"):
        out["type_hint"] = "Photoshop-IRB"
    return out

# New helper: process APP1 entries (EXIF/XMP)
def _process_app1_entries(meta: Dict[str, Any], app1_entries: List[Dict[str, Any]]) -> None:
    maker_notes_present = False
    thumbnail_evidence = {}
    for e in app1_entries:
        payload = e.pop("payload", None)
        e.pop("payload_head", None)
        parsed = {}
        if not payload:
            e["parsed"] = parsed
            continue
        # EXIF in APP1
        if payload.startswith(b"Exif\x00\x00"):
            parsed["contains"] = parsed.get("contains", []) + ["EXIF"]
            if piexif:
                try:
                    exif_dict = piexif.load(payload)
                    try:
                        exif_ifd = exif_dict.get("Exif", {})
                        if 37500 in exif_ifd:
                            maker_notes_present = True
                            parsed["maker_note_present"] = True
                        thumb = exif_dict.get("thumbnail")
                        if thumb:
                            th_hash = hashlib.sha256(thumb).hexdigest()
                            thumbnail_evidence = {"thumbnail_len": len(thumb), "thumbnail_sha256": th_hash}
                    except Exception:
                        pass
                    parsed["exif_parsed"] = _normalize_piexif_dict(exif_dict)
                except Exception as exc:
                    parsed["exif_parsed_error"] = str(exc)
            else:
                parsed["exif_parsed_error"] = "piexif not installed"
        # XMP in APP1 (may coexist)
        if b"<x:xmpmeta" in payload or b"http://ns.adobe.com/xap/1.0/" in payload:
            parsed["contains"] = parsed.get("contains", []) + ["XMP"]
            try:
                txt = payload.decode("utf-8", "replace")
                try:
                    dom = minidom.parseString(txt)
                    parsed["xmp_pretty"] = dom.toprettyxml(indent="  ")
                except Exception:
                    parsed["xmp_text"] = txt
            except Exception as exc:
                parsed["xmp_error"] = str(exc)
        # If neither heuristic matched, keep a printable snippet
        if "contains" not in parsed:
            parsed["contains"] = ["APP1-unknown"]
            parsed["ascii_preview"] = _bytes_to_printable(payload, 256)
        e["parsed"] = parsed
    if maker_notes_present:
        meta.setdefault("forensic", {})["maker_notes_present"] = True
    if thumbnail_evidence:
        meta.setdefault("forensic", {})["thumbnail"] = thumbnail_evidence

# New helper: process APP2 entries (ICC_PROFILE/MPF)
def _process_app2_entries(meta: Dict[str, Any], app2_entries: List[Dict[str, Any]]) -> None:
    icc_fragments = {}
    icc_total = None
    icc_found = False
    for e in app2_entries:
        payload = e.pop("payload", None)
        e.pop("payload_head", None)
        parsed = {}
        if not payload:
            e["parsed"] = parsed
            continue
        if payload.startswith(b"ICC_PROFILE"):
            icc_found = True
            if len(payload) >= 14:
                seq = payload[12]
                total = payload[13]
                icc_total = total if icc_total is None else icc_total
                chunk = payload[14:]
                icc_fragments[seq] = chunk
                parsed["contains"] = ["ICC_PROFILE_fragment"]
                parsed["fragment_index"] = seq
                parsed["fragment_total"] = total
            else:
                parsed["contains"] = ["ICC_PROFILE_fragment_bad"]
                parsed["ascii_preview"] = _bytes_to_printable(payload, 128)
            e["parsed"] = parsed
        elif payload.startswith(b"MPF"):
            parsed["contains"] = ["MPF"]
            parsed["ascii_preview"] = _bytes_to_printable(payload, 256)
            e["parsed"] = parsed
        else:
            parsed["contains"] = [e.get("type", "APP2")]
            parsed["ascii_preview"] = _bytes_to_printable(payload, 128)
            e["parsed"] = parsed
    if icc_found:
        try:
            if icc_total:
                seqs = range(1, icc_total + 1)
            else:
                seqs = sorted(icc_fragments.keys())
            assembled = b"".join(icc_fragments.get(i, b"") for i in seqs)
            icc_info = {}
            if ImageCms:
                try:
                    prof = ImageCms.ImageCmsProfile(io.BytesIO(assembled))
                    try:
                        desc = ImageCms.getProfileDescription(prof)
                        icc_info["description"] = desc
                    except Exception:
                        icc_info["description_error"] = "could not get description"
                except Exception as exc:
                    icc_info["error"] = f"ImageCms failed to read profile: {exc}"
            else:
                icc_info["error"] = "ImageCms not available"
            meta.setdefault("parsed_app2", {})["icc_profile"] = _make_json_serializable(icc_info)
        except Exception as exc:
            meta.setdefault("parsed_app2", {})["icc_profile_error"] = str(exc)

# New helper: final cleanup to remove any leftover raw payloads/payload_head
def _cleanup_app_payloads(meta: Dict[str, Any]) -> None:
    for name, entries in meta.get("jpeg_app_segments", {}).items():
        for e in entries:
            if "payload" in e:
                e.pop("payload", None)
    for nm in ("APP1", "APP2"):
        for e in meta.get("jpeg_app_segments", {}).get(nm, []):
            e.pop("payload_head", None)

# New helper: check conflicts between parsed EXIF pieces
def _check_exif_conflicts(meta: Dict[str, Any], app1_entries: List[Dict[str, Any]]) -> None:
    try:
        exif_parsed = None
        for e in app1_entries:
            p = e.get("parsed", {})
            if p and p.get("exif_parsed"):
                exif_parsed = p["exif_parsed"]
                break
        conflicts = []
        if exif_parsed:
            d_orig = exif_parsed.get("Exif", {}).get("DateTimeOriginal")
            d_dig = exif_parsed.get("Exif", {}).get("DateTimeDigitized")
            d_file = meta.get("exif", {}).get("DateTime")
            if d_orig and d_dig and d_orig != d_dig:
                conflicts.append("DateTimeOriginal != DateTimeDigitized")
            if d_orig and d_file and not d_orig.startswith(d_file.split(" ")[0]):
                conflicts.append("DateTimeOriginal date != File DateTime")
            gps_present = "GPS" in exif_parsed and exif_parsed["GPS"]
            if gps_present and "GPSInfo" not in meta.get("exif", {}):
                conflicts.append("GPS parsed but GPSInfo missing in top-level EXIF")
        if conflicts:
            meta.setdefault("forensic", {})["conflicts"] = conflicts
    except Exception:
        pass

def read_image_from_bytes(img_bytes: bytes) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    # file-level hashes & mime
    meta["file"] = _compute_hashes(img_bytes)
    meta["raw_header_hex"] = _raw_header_bytes(img_bytes, 128)
    # (mime_guess removed — we rely on marker/APP0 parsing instead)

    # trailing bytes after EOI
    trailing_info = _find_trailing_after_eoi(img_bytes)
    meta["trailing"] = trailing_info

    with Image.open(io.BytesIO(img_bytes)) as img:
        meta["format"] = img.format
        meta["mode"] = img.mode
        meta["size"] = img.size
        # prefer to set mime_guess from PIL format
        if img.format:
            meta["mime_guess"] = f"image/{img.format.lower()}"
        info_serializable = {}
        for k, v in img.info.items():
            if isinstance(v, (bytes, bytearray)):
                info_serializable[k] = {"type": "bytes", "length": len(v)}
                continue
            try:
                json.dumps({k: v})
                info_serializable[k] = v
            except TypeError:
                info_serializable[k] = str(v)
        meta["info"] = info_serializable
        try:
            exif = img.getexif()
            if exif and len(exif):
                meta["exif"] = _exif_to_dict(exif)
            else:
                meta["exif"] = {}
        except Exception:
            meta["exif"] = {}

        if img.format == "PNG":
            png_text: Dict[str, str] = {}
            for k, v in img.info.items():
                if isinstance(v, str):
                    png_text[k] = v
            meta["png_text"] = png_text

        meta["icc_profile_present"] = "icc_profile" in img.info

        # add low-level APPn extraction for JPEGs
        if img.format == "JPEG":
            try:
                # keep_payload=True so we can fully parse APP1 and APP2; we'll remove raw bytes before returning.
                meta["jpeg_app_segments"] = parse_jpeg_app_segments(img_bytes, wanted=(1,2,11,13), keep_payload=True)

                # --- FULL marker scan for SOF/DQT/DHT/DRI/COM and segment order/multiplicity ---
                meta["jpeg_markers"] = parse_jpeg_markers_full(img_bytes)
                # multiplicity summary
                counts: Dict[str, int] = {}
                for m in meta["jpeg_markers"]:
                    counts[m.get("name", "UNK")] = counts.get(m.get("name", "UNK"), 0) + 1
                meta["marker_counts"] = counts

                # --- FULL parsing for APP1 and APP2 using piexif / ImageCms ---
                # APP1: EXIF and/or XMP
                app1_entries = meta["jpeg_app_segments"].get("APP1", [])
                _process_app1_entries(meta, app1_entries)

                # APP2: ICC_PROFILE and MPF handling (may be split across multiple APP2 segments)
                app2_entries = meta["jpeg_app_segments"].get("APP2", [])
                _process_app2_entries(meta, app2_entries)

                # remove any remaining raw payloads if any (safety)
                _cleanup_app_payloads(meta)

                # Conflict checks (dates/software/GPS)
                _check_exif_conflicts(meta, app1_entries)

            except Exception:
                meta["jpeg_app_segments"] = {}
        
    return meta

def read_image_from_path(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return read_image_from_bytes(f.read())
    
def print_metadata(meta: Dict[str, Any]) -> None:
    print(json.dumps(meta, indent=2, default=str))

def _normalize_piexif_dict(exif_dict) -> Dict[str, Any]:
    """
    Convert piexif.load() output into a JSON-serializable dict with tag names,
    decode bytes where reasonable, and omit thumbnail binary data entirely.
    """
    out: Dict[str, Any] = {}
    if not piexif:
        return _make_json_serializable(exif_dict)

    # thumbnail hash/size detection (thumbnail stored separately in exif_dict['thumbnail'])
    thumb = exif_dict.get("thumbnail")
    if thumb:
        try:
            out["_thumbnail_sha256"] = hashlib.sha256(thumb).hexdigest()
            out["_thumbnail_length"] = len(thumb)
        except Exception:
            pass

    for ifd, tags in exif_dict.items():
        # skip thumbnail IFD entirely to avoid printing binary thumbnail data
        if ifd is None or ifd == "thumbnail":
            continue
        out_ifd: Dict[str, Any] = {}
        for tag_id, val in tags.items():
            # Map tag id -> name when available
            tag_name = None
            try:
                tag_entry = piexif.TAGS.get(ifd, {}).get(tag_id)
                if tag_entry:
                    tag_name = tag_entry["name"]
            except Exception:
                tag_name = None
            if not tag_name:
                tag_name = str(tag_id)

            # Handle binary values (omit thumbnail already handled above)
            if isinstance(val, (bytes, bytearray)):
                # try to decode text-like fields (UserComment, XP* fields, etc.)
                try:
                    decoded = val.decode("utf-8", "replace")
                    out_ifd[tag_name] = decoded
                except Exception:
                    # fallback to printable preview and length
                    out_ifd[tag_name] = {"bytes_length": len(val), "preview": _bytes_to_printable(val, 128)}
            else:
                out_ifd[tag_name] = _make_json_serializable(val)
        out[ifd] = out_ifd
    return out