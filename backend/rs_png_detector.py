#!/usr/bin/env python3
"""
Minimal RS steganalysis-style detector for PNG (spatial / pixel domain).

- Reads image pixels using Pillow
- Converts to luminance (grayscale)
- Builds a sequence of pixel intensities
- Applies RS analysis with group size 4
- Outputs R+, S+, R-, S- and a simple "suspicion score"

This is a *heuristic* detector aimed at LSB-type spatial stego in lossless images
(like classic LSB replacement/LSB matching in PNG). It will not be perfect, but
it’s a solid proof-of-concept, analogous to the JPEG DCT version.
"""

import sys
import numpy as np
from PIL import Image

GROUP_SIZE = 4  # keep the same as the JPEG version


# ----------------- RS helpers -----------------

def discrimination_func(group: np.ndarray) -> float:
    """
    Discrimination function f(G): measure of local variation.
    Classic choice: sum |x_{i+1} - x_i| for the group.
    """
    return np.sum(np.abs(np.diff(group)))


def flip_LSB_plus(c: int) -> int:
    """
    F+ flipping function on a single pixel value (0..255).

    Idea (spatial RS-style):
      - even -> +1
      - odd  -> -1
    with saturation at [0, 255].
    """
    if (c & 1) == 0:
        # even
        return c + 1 if c < 255 else 255
    else:
        # odd
        return c - 1 if c > 0 else 0


def flip_LSB_minus(c: int) -> int:
    """
    F- flipping function (roughly inverse of F+).

    Idea:
      - even -> -1
      - odd  -> +1
    with saturation at [0, 255].
    """
    if (c & 1) == 0:
        # even
        return c - 1 if c > 0 else 0
    else:
        # odd
        return c + 1 if c < 255 else 255


def classify_group(group: np.ndarray, flip_func) -> str:
    """
    Classify a group G as:
      - 'R' (Regular) if f(F(G)) > f(G)
      - 'S' (Singular) if f(F(G)) < f(G)
      - 'U' (Unusable) if equal

    flip_func is either flip_LSB_plus or flip_LSB_minus.
    """
    fG = discrimination_func(group)
    flipped = np.array([flip_func(int(c)) for c in group], dtype=np.int32)
    fF = discrimination_func(flipped)

    if fF > fG:
        return 'R'
    elif fF < fG:
        return 'S'
    else:
        return 'U'


# ----------------- PNG pixel extraction -----------------

def get_pixel_sequence(path: str) -> np.ndarray:
    """
    Extract a long 1D sequence of grayscale pixel values (0..255).

    - Loads the image using Pillow
    - Converts to 8-bit grayscale ("L")
    - Flattens to a 1D array

    This yields a sequence suitable for grouping in RS analysis.
    """
    img = Image.open(path)
    img = img.convert("L")  # luminance / grayscale
    arr = np.array(img, dtype=np.int32)
    return arr.flatten()


# ----------------- RS analysis core -----------------

def rs_analysis(samples: np.ndarray, group_size: int = GROUP_SIZE):
    """
    Perform RS analysis on a 1D sample array (pixel values).

    Returns:
        R_plus, S_plus, R_minus, S_minus, U_plus, U_minus
    """
    # Truncate to multiple of group_size
    n_groups = len(samples) // group_size
    samples = samples[:n_groups * group_size]
    groups = samples.reshape(n_groups, group_size)

    R_plus = S_plus = U_plus = 0
    R_minus = S_minus = U_minus = 0

    for g in groups:
        # F+ classification
        c_plus = classify_group(g, flip_LSB_plus)
        if c_plus == 'R':
            R_plus += 1
        elif c_plus == 'S':
            S_plus += 1
        else:
            U_plus += 1

        # F- classification
        c_minus = classify_group(g, flip_LSB_minus)
        if c_minus == 'R':
            R_minus += 1
        elif c_minus == 'S':
            S_minus += 1
        else:
            U_minus += 1

    return R_plus, S_plus, R_minus, S_minus, U_plus, U_minus


def rs_suspicion_score(Rp, Sp, Rm, Sm) -> float:
    """
    A simple heuristic "suspicion" score based on RS asymmetry.

    For clean images, (Rp - Sp) and (Rm - Sm) are usually similar;
    for LSB-type stego, this symmetry is disturbed.

    We measure normalized difference:
        score = | (Rp - Sp) - (Rm - Sm) | / total_groups

    Higher score => more suspicious.
    """
    total = Rp + Sp + Rm + Sm
    if total == 0:
        return 0.0
    diff = abs((Rp - Sp) - (Rm - Sm))
    return diff / total


def analyze_png(path: str):
    samples = get_pixel_sequence(path)

    if len(samples) < GROUP_SIZE * 100:
        print("Warning: very few usable samples; results may be unreliable.")

    Rp, Sp, Rm, Sm, Up, Um = rs_analysis(samples, group_size=GROUP_SIZE)
    score = rs_suspicion_score(Rp, Sp, Rm, Sm)

    print(f"File: {path}")
    print(f"Total groups (used): {Rp + Sp + Up}")  # per F+ (same as per F-)
    print(f"R+ = {Rp}, S+ = {Sp}, U+ = {Up}")
    print(f"R- = {Rm}, S- = {Sm}, U- = {Um}")
    print(f"Suspicion score (0 = clean-looking, higher = more suspicious): {score:.6f}")

    # Same rough rule-of-thumb threshold as the JPEG version
    if score > 0.01:
        print("Result: Image looks SUSPICIOUS (possible spatial LSB stego).")
    else:
        print("Result: Image looks LIKELY CLEAN (no strong RS evidence of spatial LSB stego).")


# ----------------- CLI -----------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python rs_png_detector.py <image.png>")
        sys.exit(1)
    analyze_png(sys.argv[1])
