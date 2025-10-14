#!/usr/bin/env python3

import sys
import os
import json
import struct
import binascii
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

try:
    import piexif
    _HAS_PIEXIF = True
except Exception:
    _HAS_PIEXIF = False

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'

KNOWN_CHUNKS = {
    # Critical
    "IHDR", "PLTE", "IDAT", "IEND",
    # Ancillary 
    "bKGD", "cHRM", "dSIG", "eXIf", "gAMA", "hIST", "iCCP", "iTXt",
    "pHYs", "sBIT", "sPLT", "sRGB", "tEXt", "tIME", "tRNS", "zTXt",
    # APNG
    "acTL", "fcTL", "fdAT",
}

ALIASES = {
    "eXIf": "EXIF"
}

def _file_hashes(path: str) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk)
            sha.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha.hexdigest()}

def print_metadata(meta: dict) -> None:
    print(json.dumps(meta, indent=2))

def chunk_flags(chunk_type: str) -> Dict[str, bool]:
    if len(chunk_type) != 4 or not chunk_type.isascii():
        return {"ancillary": False, "private": False, "reserved_upper": False, "safe_to_copy": False}
    
    def is_lower(c): return "a" <= c <= "z"
    def is_upper(c): return "A" <= c <= "Z"

    return {
        "ancillary": is_lower(chunk_type[0]),
        "private": is_lower(chunk_type[1]),
        "reserved_upper": is_upper(chunk_type[2]),
        "safe_to_copy": is_lower(chunk_type[3]),
    }

@dataclass
class ChunkInfo:
    index: int
    offset: int
    length: int
    type: str
    crc_hex: str
    crc_ok: bool
    ancillary: bool
    private: bool
    reserved_upper: bool
    safe_to_copy: bool

def read_exact(f, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise EOFError("Unexpected EOF while reading PNG file")
    return b

def _flatten_exif_from_piexif(ed: dict) -> Dict[str, Any]:
    IMG = ed.get("0th", {}) if isinstance(ed, dict) else {}
    EXF = ed.get("Exif", {}) if isinstance(ed, dict) else {}

    def get(tagset, tagid):
        return tagset.get(tagid)
    def rational_to_list(v):
        if isinstance(v, tuple) and len(v) == 2:
            n, d = v
            return [int(n), int (d)]
        if isinstance(v, list) and v and isinstance(v[0], tuple):
            n, d = v[0]
            return [int(n), int(d)]
        return v
    
    flat = {}

    if 271 in IMG: flat["Make"] = IMG[271].decode("utf-8", "ignore") if isinstance(IMG[271], bytes) else IMG[271]
    if 272 in IMG: flat["Model"] = IMG[272].decode("utf-8", "ignore") if isinstance(IMG[272], bytes) else IMG[272]
    if 274 in IMG: flat["Orientation"] = IMG[274]
    if 282 in IMG: flat["XResolution"] = rational_to_list(IMG[282])
    if 283 in IMG: flat["YResolution"] = rational_to_list(IMG[283])
    if 305 in IMG: flat["Software"] = IMG[305].decode("utf-8", "ignore") if isinstance(IMG[305], bytes) else IMG[305]

    #ExifIFD
    if 36867 in EXF: flat["DateTimeOriginal"] = EXF[36867].decode("utf-8", "ignore") if isinstance(EXF[36867], bytes) else EXF[36867]
    if 33437 in EXF: flat["FNumber"] = rational_to_list(EXF[33437])
    if 33434 in EXF: flat["ExposureTime"] = rational_to_list(EXF[33434])
    if 37386 in EXF: flat["FocalLength"] = rational_to_list(EXF[37386])
    if 34855 in EXF: flat["ISOSpeedRatings"] = EXF[34855]

    return flat

def parse_png(path: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "file": path,
        "file_size": None,
        "valid_signature": False,
        "chunks": [],
        "markers": {},
        "duplicates": {},
        "unknown_ancillary_chunks": [],
        "iend_index": None,
        "trailing_bytes": 0,
        "trailing_bytes": 0,
        "trailing_hexdump": None,
        "ihdr": None,
        "size": None,
        "exif": None,
        "exif_raw_len": None,
        "exif_error": None,
    }

    file_size = os.path.getsize(path)
    result["file_size"] = file_size
    _hashes = _file_hashes(path)
    result["file"] = {
        "path": path,
        "size": file_size,
        "md5": _hashes["md5"],
        "sha256": _hashes["sha256"],
    }

    with open(path, "rb") as f:
        sig = read_exact(f, 8)
        result["valid_signature"] = (sig == PNG_SIGNATURE)
        if not result["valid_signature"]:
            raise ValueError("Invalid PNG signature. This is not a valid PNG file.")
        
        chunks: List[ChunkInfo] = []
        offset = 8
        index = 0
        iend_seen_at: Optional[int] = None
        ihdr_payload: Optional[bytes] = None
        exif_payload: Optional[bytes] = None

        while True:
            try:
                length_bytes = f.read(4)
                if not length_bytes or len(length_bytes) < 4:
                    break
                length = struct.unpack(">I", length_bytes)[0]
                type_bytes = read_exact(f, 4)
                ctype = type_bytes.decode("latin-1")
                data = read_exact(f, length)
                crc_bytes = read_exact(f, 4)
                crc_read = struct.unpack(">I", crc_bytes)[0]

                crc_calc = binascii.crc32(type_bytes)
                crc_calc = binascii.crc32(data, crc_calc) & 0xffffffff
                crc_ok = (crc_calc == crc_read)

                flags = chunk_flags(ctype)
                chunk = ChunkInfo(
                    index=index,
                    offset=offset,
                    length=length,
                    type=ctype,
                    crc_hex=f"{crc_read:08X}",
                    crc_ok=crc_ok,
                    ancillary=flags["ancillary"],
                    private=flags["private"],
                    reserved_upper=flags["reserved_upper"],
                    safe_to_copy=flags["safe_to_copy"],
                )
                chunks.append(chunk)

                if ctype == "IHDR":
                    ihdr_payload = data
                elif ctype in ("eXIf", "eXIf"):
                    exif_payload = data
                if ctype == "IEND" and iend_seen_at is None:
                    iend_seen_at = index

                offset += 12 + length
                index += 1

                if ctype == "IEND":
                    break

            except EOFError:
                break

        result["chunks"] = [asdict(c) for c in chunks]
        result["iend_index"] = iend_seen_at

        if iend_seen_at is not None:
            iend_chunk = chunks[iend_seen_at]
            end_of_iend = iend_chunk.offset + 12 + iend_chunk.length
            trailing = file_size - end_of_iend
            if trailing > 0:
                result["trailing_bytes"] = trailing
                
                with open(path, "rb") as f2:
                    f2.seek(end_of_iend)
                    tb = f2.read(trailing)
                    result["trailing_hexdump"] = tb.hex()
        else:
            result["trailing_bytes"] = max(0, file_size - offset)

        type_counts: Dict[str, int] = {}
        for c in chunks:
            type_counts[c.type] = type_counts.get(c.type, 0) + 1
        result["duplicates"] = {t: n for t, n in type_counts.items() if n > 1}

        requested = [
            "IHDR", "eXIf", "eXlf", "iTXt", "tEXt", "zTXt", "tIME", "iCCP", "pHYs",
            "acTL", "fcTL", "fdAT", "IEND"
        ]

        normalized = {a: ALIASES.get(a, a) for a in requested}

        markers: Dict[str, Any] = {}
        for raw, norm in normalized.items():
            positions = [c.index for c in chunks if c.type == norm or c.type == raw]
            markers[raw] = {
                "normalized_to": norm if norm != raw else None,
                "present": len(positions) > 0,
                "count": len(positions),
                "positions": positions,
            }
        result["markers"] = markers

        unknown_anc = []
        for c in chunks:
            cname = ALIASES.get(c.type, c.type)
            if c.ancillary and cname not in KNOWN_CHUNKS:
                unknown_anc.append({
                    "type": c.type,
                    "index": c.index,
                    "length": c.length,
                })
        result["unknown_ancillary_chunks"] = unknown_anc

        if ihdr_payload and len(ihdr_payload) == 13:
            w, h, bit_depth, color_type, comp, filt, inter = struct.unpack(">IIBBBBB", ihdr_payload)
            result["ihdr"] = {
                "width": w,
                "height": h,
                "bit_depth": bit_depth,
                "color_type": color_type,
                "compression": comp,
                "filter": filt,
                "interlace": inter,
            }
            result["size"] = (int(w), int(h))

        if exif_payload is not None:
            result["exif_raw_len"] = len(exif_payload)
            if _HAS_PIEXIF:
                try:
                    edict = piexif.load(exif_payload)
                    result["exif"] = _flatten_exif_from_piexif(edict)
                except Exception as e:
                    try:
                        prefixed = b"Exif\x00\x00" + exif_payload
                        edict = piexif.load(prefixed)
                        result["exif"] = _flatten_exif_from_piexif(edict)
                    except Exception as e2:
                        result["exif_error"] = f"Failed to parse EXIF data: {str(e2)}"
            else:
                result["exif_error"] = "piexif not installed; returning raw length only"
            
    return result

def hexdump(b: bytes, width: int = 16) -> str:
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hexpart = " ".join(f"{x:02x}" for x in chunk)
        asciipart = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append(f"{i:08x}  {hexpart:<{width*3}}  |{asciipart}|")

def read_image_from_path(path: str) -> dict:
    return parse_png(path)

def read_image_from_bytes(data: bytes) -> dict:
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        return parse_png(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

def main(argv: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Parse PNG chunks and report metadata.")
    p.add_argument("png_path", help="Path to PNG file")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--hexdump", action="store_true", help="Include a short hexdump of trailing bytes (if any)")
    args = p.parse_args(argv[1:])

    info = parse_png(args.png_path)

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    # Human-readable report
    print(f"File: {info['file']}  ({info['file_size']} bytes)")
    print(f"Valid PNG signature: {info['valid_signature']}")
    if info.get("ihdr"):
        ih = info["ihdr"]
        print(f"IHDR: {ih['width']}x{ih['height']} bit_depth={ih['bit_depth']} color_type={ih['color_type']} compression={ih['compression']} filter={ih['filter']} interlace={ih['interlace']}")
    print()

    # Markers summary
    print("Requested markers:")
    for k, v in info["markers"].items():
        alias = f" -> {v['normalized_to']}" if v["normalized_to"] else ""
        print(f"{k}{alias}: present={v['present']} count={v['count']} positions={v['positions']}")
    print()

    # Unknown ancillary chunks
    if info["unknown_ancillary_chunks"]:
        print("Unknown ancillary chunks:")
        for u in info["unknown_ancillary_chunks"]:
            print(f"  index={u['index']:3d} type={u['type']} length={u['length']}")
        print()
    else:
        print("Unknown ancillary chunks: none\n")

    # Duplicates
    if info["duplicates"]:
        print("Duplicate chunk types:")
        for t, n in info["duplicates"].items():
            print(f"  {t}: {n} occurrences")
        print()
    else:
        print("Duplicate chunk types: none\n")

    # Chunks table
    print("Chunk listing (in file order):")
    header = f"{'idx':>3}  {'off':>10}  {'len':>8}  {'type':>4}  {'crc_ok':>6}  {'anc':>3}  {'priv':>4}  {'resv':>4}  {'safe':>4}"
    print(header)
    print("-" * len(header))
    for c in info["chunks"]:
        print(f"{c['index']:3d}  {c['offset']:10d}  {c['length']:8d}  {c['type']:>4}  {str(c['crc_ok']):>6}"
              f"  {('y' if c['ancillary'] else 'n'):>3}  {('y' if c['private'] else 'n'):>4}  {('Y' if c['reserved_upper'] else 'n'):>4}  {('y' if c['safe_to_copy'] else 'n'):>4}")
    print()

    # Trailing bytes
    print(f"IEND index: {info['iend_index']}")
    print(f"Trailing bytes after IEND: {info['trailing_bytes']}")
    if args.hexdump and info.get("trailing_hexdump"):
        tb = bytes.fromhex(info["trailing_hexdump"])
        # Render a short hexdump
        print("\nTrailing bytes (up to 64 bytes):")
        print(hexdump(tb))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))