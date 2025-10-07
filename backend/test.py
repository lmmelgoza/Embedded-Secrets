#!/usr/bin/env python3
import sys
import image_read
from organize_meta import pretty_print_meta

def main(path: str = None):
    if path is None:
        path = "Canon_40D.jpg"  # default test image in backend/
    meta = image_read.read_image_from_path(path)
    pretty_print_meta(meta)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)