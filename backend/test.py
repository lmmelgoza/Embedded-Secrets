#!/usr/bin/env python3
import sys
from image_read import read_image_from_path, print_metadata

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_read.py /path/to/image.jpg")
        sys.exit(1)
    path = sys.argv[1]
    meta = read_image_from_path(path)
    print_metadata(meta)