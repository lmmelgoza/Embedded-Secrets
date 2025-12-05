#!/usr/bin/env python3
"""
Minimal RS steganalysis-style detector for JPEG (DCT domain).

- Reads JPEG DCT coefficients using jpegio
- Builds a sequence of non-zero AC coefficients
- Applies RS analysis with group size 4
- Outputs R+, S+, R-, S- and a simple "suspicion score"

This is a *heuristic* detector aimed at LSB-type DCT stego (like JSteg, parity-based
methods, etc.). It will not be perfect, but it’s a solid proof-of-concept.
"""

import sys
import numpy as np
import jpegio as jio

GROUP_SIZE = 4  # classic RS often uses 4; can tune if you like


# ----------------- RS helpers -----------------

def discrimination_func(group: np.ndarray) -> float:
    """
    Discrimination function f(G): measure of local variation.
    Classic choice: sum |x_{i+1} - x_i| for the group.
    """
    return np.sum(np.abs(np.diff(group)))


def flip_LSB_plus(c: int) -> int:
    """
    F+ flipping function on a single coefficient.
    Intuition: move coefficient by +/-1 depending on its parity,
    but in a way that mimics incrementing in the spatial RS papers.

    We ignore zeros (return unchanged) – they don't carry LSB embedding.
    """
    if c == 0:
        return 0
    if c > 0:
        # even -> +1, odd -> -1
        return c + 1 if (c & 1) == 0 else c - 1
    else:
        # c < 0: even -> -1, odd -> +1
        return c - 1 if (c & 1) == 0 else c + 1


def flip_LSB_minus(c: int) -> int:
    """
    F- flipping function (roughly inverse of F+).
    """
    if c == 0:
        return 0
    if c > 0:
        # even -> -1, odd -> +1
        return c - 1 if (c & 1) == 0 else c + 1
    else:
        # c < 0: even -> +1, odd -> -1
        return c + 1 if (c & 1) == 0 else c - 1


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


# ----------------- JPEG DCT extraction -----------------

def get_ac_sequence(jpeg, restrict_mid_freq: bool = True) -> np.ndarray:
    """
    Extract a long 1D sequence of non-zero AC coefficients from the luminance (Y) component.

    - We process 8x8 DCT blocks.
    - We skip the DC term (index 0).
    - Optionally we restrict to a subset of mid-frequency positions.

    This yields a sequence suitable for grouping in RS analysis.
    """
    # Use luminance component (component 0)
    coef = jpeg.coef_arrays[0]
    h, w = coef.shape

    # Indices 0..63 in flattened 8x8 block; 0 is DC, 1..63 are AC.
    # For RS, it often helps to ignore very low and very high frequencies.
    if restrict_mid_freq:
        # Keep a mid-band: indices 5..32 for example (tunable)
        valid_indices = [i for i in range(1, 64) if 5 <= i <= 32]
    else:
        valid_indices = [i for i in range(1, 64)]

    seq = []

    for by in range(0, h, 8):
        for bx in range(0, w, 8):
            block = coef[by:by+8, bx:bx+8].flatten()
            for k in valid_indices:
                c = int(block[k])
                if c != 0:
                    seq.append(c)

    return np.array(seq, dtype=np.int32)


# ----------------- RS analysis core -----------------

def rs_analysis(coeffs: np.ndarray, group_size: int = GROUP_SIZE):
    """
    Perform RS analysis on a 1D coefficient array.

    Returns:
        R_plus, S_plus, R_minus, S_minus, U_plus, U_minus
    """
    # Truncate to multiple of group_size
    n_groups = len(coeffs) // group_size
    coeffs = coeffs[:n_groups * group_size]
    groups = coeffs.reshape(n_groups, group_size)

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


def analyze_jpeg(path: str):
    jpeg = jio.read(path)
    coeffs = get_ac_sequence(jpeg, restrict_mid_freq=True)

    if len(coeffs) < GROUP_SIZE * 100:
        print("Warning: very few usable coefficients; results may be unreliable.")

    Rp, Sp, Rm, Sm, Up, Um = rs_analysis(coeffs, group_size=GROUP_SIZE)
    score = rs_suspicion_score(Rp, Sp, Rm, Sm)

    print(f"File: {path}")
    print(f"Total groups (used): {Rp + Sp + Up}")  # per F+ (same as per F-)
    print(f"R+ = {Rp}, S+ = {Sp}, U+ = {Up}")
    print(f"R- = {Rm}, S- = {Sm}, U- = {Um}")
    print(f"Suspicion score (0 = clean-looking, higher = more suspicious): {score:.6f}")

    # Very rough rule-of-thumb threshold (you would tune this on a dataset!)
    if score > 0.01:
        print("Result: Image looks SUSPICIOUS (possible DCT LSB stego).")
    else:
        print("Result: Image looks LIKELY CLEAN (no strong RS evidence of DCT stego).")


# ----------------- CLI -----------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python rs_jpeg_detector.py <image.jpg>")
        sys.exit(1)
    analyze_jpeg(sys.argv[1])
