#!/usr/bin/env python3
import io
import json 
from typing import Any, Dict, Iterable
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

def read_image_from_bytes(img_bytes: bytes) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    with Image.open(io.BytesIO(img_bytes)) as img:
        meta["format"] = img.format
        meta["mode"] = img.mode
        meta["size"] = img.size
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

                # --- FULL parsing for APP1 and APP2 using piexif / ImageCms ---
                # APP1: EXIF and/or XMP
                app1_entries = meta["jpeg_app_segments"].get("APP1", [])
                for e in app1_entries:
                    payload = e.pop("payload", None)
                    # remove hex payload_head after parsing (user requested no hex payload printed)
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
                                # parse with piexif and normalize (thumbnail data will be omitted)
                                exif_dict = piexif.load(payload)
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

                # APP2: ICC_PROFILE and MPF handling (may be split across multiple APP2 segments)
                app2_entries = meta["jpeg_app_segments"].get("APP2", [])
                # collect ICC_PROFILE fragments
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
                        # header is "ICC_PROFILE" + null (11+1=12), then seq (1 byte) then count (1 byte)
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
                        # store a short preview; full MPF parsing is out of scope here
                        parsed["ascii_preview"] = _bytes_to_printable(payload, 256)
                        e["parsed"] = parsed
                    else:
                        parsed["contains"] = [e.get("type", "APP2")]
                        parsed["ascii_preview"] = _bytes_to_printable(payload, 128)
                        e["parsed"] = parsed

                # If we found ICC fragments, assemble them and parse with ImageCms
                if icc_found:
                    # assemble by seq (sequence numbers usually start at 1)
                    try:
                        # determine expected range from icc_total if available else use max key
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
                        # attach assembled info at top-level for convenience
                        meta.setdefault("parsed_app2", {})["icc_profile"] = _make_json_serializable(icc_info)
                    except Exception as exc:
                        meta.setdefault("parsed_app2", {})["icc_profile_error"] = str(exc)

                # remove any remaining raw payloads if any (safety)
                for name, entries in meta["jpeg_app_segments"].items():
                    for e in entries:
                        if "payload" in e:
                            e.pop("payload", None)
                # remove any leftover payload_head for APP1/APP2 (user asked to not print hex payload after parsing)
                for nm in ("APP1", "APP2"):
                    for e in meta["jpeg_app_segments"].get(nm, []):
                        e.pop("payload_head", None)

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