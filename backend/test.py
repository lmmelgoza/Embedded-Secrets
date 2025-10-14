#!/usr/bin/env python3
import sys, json
import image_read
import organize_meta as omjpg
import organize_png_meta as ompng
import png_read

def sniff_format(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(8)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if head[:2] == b"\xff\xD8":
        return "JPEG"
    return "UNKNOWN"

def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python test.py <image-path>")
    path = sys.argv[1]
    kind = sniff_format(path)

    if kind == "PNG":
        meta = png_read.read_image_from_path(path)
        ompng.pretty_print_meta(meta)
    elif kind == "JPEG":
        meta = image_read.read_image_from_path(path)
        omjpg.pretty_print_meta(meta)
    else:
        # Fallback: try JPEG then PNG, then just dump JSON
        try:
            meta = image_read.read_image_from_path(path)
            omjpg.pretty_print_meta(meta)
        except Exception:
            try:
                meta = png_read.read_image_from_path(path)
                ompng.pretty_print_meta(meta)
            except Exception:
                print(json.dumps({"error": "Unsupported or unreadable image format", "file": path}, indent=2))

if __name__ == "__main__":
    main()