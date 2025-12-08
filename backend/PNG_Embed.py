#!/usr/bin/env python3
# PNG_DCT_Embed.py
#
# Minimal external DCT-domain watermarking for PNGs (and other rasters).
# - AES-GCM + scrypt KDF (same spirit as your JPEG code)
# - Password-derived RNG to pick coefficient positions
# - QIM in mid-frequency DCT coefficients on 8x8 luminance blocks
#
# Usage:
#   Embed : python3 PNG_DCT_Embed.py embed <input.png> <output.png> "<message>" "<password>"
#   Extract: python3 PNG_DCT_Embed.py extract <input.png> "<password>"
#
# Notes:
# - Uses OpenCV for IO and DCT. Works with PNG, BMP, TIFF, etc.
# - Only full 8x8 blocks are watermarked; any right/bottom remainders are copied unchanged.

import sys
import struct
import hashlib
import numpy as np
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import cv2
import json

MAGIC = b'PD1'           # PNG DCT v1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16

# DCT/QIM settings
BLOCK = 8
DELTA = 12.0  # QIM step (tune: higher = more robust, more visible; 6–12 is a good start)

# Mid-band coefficient choices (excluding DC and very high freq); (u,v) with 0<=u,v<8
MID_BAND = [(2,3), (3,2), (1,3), (3,1), (2,2), (1,4), (4,1), (2,4), (4,2), (3,3)]

# ---------- Crypto helpers (same structure as your JPEG tool) ----------
def _derive_key(password: str, salt: bytes) -> bytes:
    return scrypt(password.encode("utf-8"), salt, 32, N=2**15, r=8, p=1)

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_LEN)
    key = _derive_key(password, salt)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return salt + nonce + tag + ct

def decrypt_bytes(packed: bytes, password: str) -> bytes:
    salt = packed[:SALT_LEN]
    nonce = packed[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag = packed[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
    ct = packed[SALT_LEN + NONCE_LEN + TAG_LEN:]
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ct, tag)
    return plain

def _seed_from_password(password: str) -> int:
    h = hashlib.sha256(password.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big")

# ---------- Bit helpers ----------
def _bytes_to_bits(b: bytes) -> np.ndarray:
    """
    Convert bytes -> bit array (MSB first per byte) reliably across numpy versions.
    """
    bits = np.zeros(len(b) * 8, dtype=np.uint8)
    for i, byte in enumerate(b):
        for j in range(8):
            # MSB first: bit 7 down to 0
            bits[i * 8 + j] = (byte >> (7 - j)) & 1
    return bits

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    """
    Convert bit array (MSB first per byte) -> bytes.
    """
    n = len(bits)
    if n % 8 != 0:
        raise ValueError("Number of bits is not a multiple of 8")
    out = bytearray(n // 8)
    for i in range(n // 8):
        val = 0
        base = i * 8
        for j in range(8):
            val = (val << 1) | int(bits[base + j])
        out[i] = val
    return bytes(out)

# ---------- DCT/QIM helpers ----------
def _qim_embed(c: float, bit: int, delta: float) -> float:
    """
    Quantization Index Modulation:
    Map coefficient into intervals centered at 0.25*Δ (bit=0) or 0.75*Δ (bit=1).
    """
    q = np.floor(c / delta)
    center = 0.75 * delta if bit else 0.25 * delta
    return q * delta + center

def _qim_decode_bit(c: float, delta: float) -> int:
    """
    Decode by checking which center (0.25Δ vs 0.75Δ) it's closer to.
    """
    frac = c / delta - np.floor(c / delta)  # in [0,1)
    # closer to 0.75 (bit=1) if frac > 0.5; else closer to 0.25 (bit=0)
    return 1 if frac > 0.5 else 0

def _to_blocks_y(image_bgr: np.ndarray):
    """
    Convert to Y channel (YCrCb), return float32 Y, and block grid size.
    We center around 128 (like JPEG) for numerically stable DCT.
    """
    ycrcb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2YCrCb)
    Y = ycrcb[..., 0].astype(np.float32) - 128.0
    h, w = Y.shape
    H = h - (h % BLOCK)
    W = w - (w % BLOCK)
    return Y[:H, :W], ycrcb[:H, :W, 1], ycrcb[:H, :W, 2], (H, W)

def _from_blocks_y(Y_emb: np.ndarray, Cr: np.ndarray, Cb: np.ndarray, original_bgr: np.ndarray, H: int, W: int):
    """
    Combine modified Y with original chroma (Cr,Cb) and untouched borders if present.
    """
    out = original_bgr.copy()
    ycrcb = cv2.cvtColor(out, cv2.COLOR_BGR2YCrCb)
    ycrcb[:H, :W, 0] = np.clip(Y_emb + 128.0, 0, 255).astype(np.uint8)
    ycrcb[:H, :W, 1] = Cr
    ycrcb[:H, :W, 2] = Cb
    return cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)

def _collect_positions(H: int, W: int, coeffs_per_block: int, seed: int):
    """
    Deterministic list of embedding positions across blocks:
    Returns a list of (by, bx, (u,v)) in a shuffled order given the seed.
    """
    import random
    rng = random.Random(seed)
    by_max = H // BLOCK
    bx_max = W // BLOCK

    if coeffs_per_block > len(MID_BAND):
        raise ValueError(f"coeffs_per_block = {coeffs_per_block} exceeds number of available " f"mid-band positions ({len(MID_BAND)}).")

    # Pre-pick coefficient coordinates per block using RNG
    # (repeat pattern to allow >1 coeff per block if desired)
    coords = []
    for by in range(by_max):
        for bx in range(bx_max):
            uvs = rng.sample(MID_BAND, coeffs_per_block)
            # choose coeff positions for this block
            for uv in uvs:
                coords.append((by, bx, uv))

    rng.shuffle(coords)
    return coords

def _header_positions(H: int, W: int):
    """
    Fixed deterministic positions for header (one coeff per block),
    using the first mid-band coordinate in row-major block order.
    """
    coords = []
    by_max = H // BLOCK
    bx_max = W // BLOCK
    uv = MID_BAND[0]
    for by in range(by_max):
        for bx in range(bx_max):
            coords.append((by, bx, uv))
    return coords

# ---------- Core embed/extract ----------
def embed(in_path: str, out_path: str, plaintext: str, password: str, coeffs_per_block: int = None):
    img = cv2.imread(in_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Could not read image: {in_path}")

    Y, Cr, Cb, (H, W) = _to_blocks_y(img)

    # payload prep (ciphertext only - header will be separate)
    payload_enc = encrypt_bytes(plaintext.encode("utf-8"), password)
    length = len(payload_enc)

    # header will carry MAGIC + length + coeffs_per_block (2 bytes unsigned)
    header_len_bytes = 3 + 4 + 2  # MAGIC(3) + length(4) + coeffs_per_block(2)
    header_bits_needed = header_len_bytes * 8

    # basic counts
    num_blocks = (H // BLOCK) * (W // BLOCK)
    if num_blocks == 0:
        raise ValueError("Image too small for 8x8 DCT blocks")

    # payload bits (exclude header)
    payload_bits = _bytes_to_bits(payload_enc)

    seed = _seed_from_password(password)

    # determine a minimal coeffs_per_block that yields enough capacity after reserving header positions
    header_positions = _header_positions(H, W)
    if header_bits_needed > len(header_positions):
        raise ValueError("Not enough blocks to store header - image too small")

    # starting guess: how many coeffs per block needed ignoring header reservation
    import math
    needed_per_block = int(math.ceil(payload_bits.size / num_blocks))
    coeff_guess = max(1, needed_per_block) if coeffs_per_block is None else coeffs_per_block

    # loop until we have enough positions for payload after excluding header positions
    while True:
        positions_payload = _collect_positions(H, W, coeffs_per_block=coeff_guess, seed=seed)
        # remove any positions that collide with header positions
        header_set = set(header_positions)
        positions_filtered = [p for p in positions_payload if p not in header_set]
        if len(positions_filtered) >= payload_bits.size:
            coeffs_final = coeff_guess
            positions_payload = positions_filtered
            break
        # otherwise bump and retry
        coeff_guess += 1
        # sanity cap (avoid infinite loop)
        if coeff_guess > 65535:
            raise ValueError("Unable to find sufficient capacity (coeffs_per_block would exceed 65535)")

    # Build header bytes now that coeffs_final is known
    header_bytes = MAGIC + struct.pack(">I", length) + struct.pack(">H", coeffs_final)
    header_bits = _bytes_to_bits(header_bytes)

    # informational JSON lines (previously printed human-readable lines)
    print(json.dumps({"seed": seed}))
    print(json.dumps({"num_blocks": int(num_blocks)}))
    print(json.dumps({"header_bytes": int(header_len_bytes)}))
    print(json.dumps({"chosen_coeffs_per_block": int(coeffs_final)}))
    print(json.dumps({"capacity_bits_after_header": int(len(positions_payload))}))
    print(json.dumps({"delta": float(DELTA)}))

    # embed header bits into header_positions (row-major order)
    Yw = Y.copy()
    bit_idx = 0
    for (by, bx, (u, v)) in header_positions:
        if bit_idx >= header_bits.size:
            break
        y0, x0 = by * BLOCK, bx * BLOCK
        block = Yw[y0:y0+BLOCK, x0:x0+BLOCK]
        dct = cv2.dct(block)
        dct[u, v] = _qim_embed(dct[u, v], int(header_bits[bit_idx]), DELTA)
        Yw[y0:y0+BLOCK, x0:x0+BLOCK] = cv2.idct(dct)
        bit_idx += 1

    if bit_idx < header_bits.size:
        raise ValueError("Failed to write full header")

    # embed payload bits into positions_payload
    bit_idx = 0
    for (by, bx, (u, v)) in positions_payload:
        if bit_idx >= payload_bits.size:
            break
        y0, x0 = by * BLOCK, bx * BLOCK
        block = Yw[y0:y0+BLOCK, x0:x0+BLOCK]
        dct = cv2.dct(block)
        dct[u, v] = _qim_embed(dct[u, v], int(payload_bits[bit_idx]), DELTA)
        Yw[y0:y0+BLOCK, x0:x0+BLOCK] = cv2.idct(dct)
        bit_idx += 1

    if bit_idx < payload_bits.size:
        raise ValueError(f"Not enough capacity (wrote {bit_idx}/{payload_bits.size} payload bits).")

    # reconstruct and save
    out_bgr = _from_blocks_y(Yw, Cr, Cb, img, H, W)
    ok = cv2.imwrite(out_path, out_bgr)
    if not ok:
        raise ValueError(f"Failed to write output: {out_path}")

    # output JSON lines similar to JPEG_Embed
    print(json.dumps({"input_path": in_path}))
    print(json.dumps({"output_path": out_path}))
    print(json.dumps({"bytes_embedded": len(plaintext)}))
    # optionally include ciphertext length for debugging
    # print(json.dumps({"ciphertext_bytes": length}))

    # --- verification step: read packed bytes back and compare to original ---
    try:
        packed_read = _read_packed_from_image(out_path, password, coeffs_per_block=coeffs_final)
    except Exception as e:
        print(json.dumps({"warning": str(e)}))
        return

    if packed_read != payload_enc:
        # compute basic diagnostics
        b1 = payload_enc
        b2 = packed_read
        minlen = min(len(b1), len(b2))
        byte_diffs = sum(1 for i in range(minlen) if b1[i] != b2[i]) + abs(len(b1) - len(b2))
        bit_diffs = 0
        first_mismatch = None
        # bit-level comparison up to minlen
        for i in range(minlen):
            xb = b1[i] ^ b2[i]
            if xb != 0:
                for bitpos in range(8):
                    if (xb >> bitpos) & 1:
                        bit_diffs += 1
                        if first_mismatch is None:
                            first_mismatch = (i, 7 - bitpos)  # MSB-first report
        # emit structured diagnostics then raise
        print(json.dumps({
            "verification_failed": True,
            "byte_diffs": int(byte_diffs),
            "bit_diffs": int(bit_diffs),
            "first_mismatch": first_mismatch
        }))
        print(json.dumps({"suggestion": "Increase DELTA (e.g. to 12 or 16) or use repetition/ECC for robustness."}))
        raise ValueError("Stego verification failed: extracted packed payload != original")
    else:
        print(json.dumps({"verification": "ok", "note": "packed payload matches original (AES-GCM decrypt should succeed)"}))

def extract(stego_path: str, password: str, coeffs_per_block: int = None) -> str:
    img = cv2.imread(stego_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Could not read image: {stego_path}")

    Y, Cr, Cb, (H, W) = _to_blocks_y(img)

    seed = _seed_from_password(password)

    header_len_bytes = 3 + 4 + 2
    header_bits_needed = header_len_bytes * 8

    header_positions = _header_positions(H, W)
    if header_bits_needed > len(header_positions):
        raise ValueError("File capacity too small or not stego (header missing)")

    print(json.dumps({"seed": seed}))
    print(json.dumps({"delta": float(DELTA)}))

    # Read header bits from fixed header positions
    bits_read = []
    for i in range(header_bits_needed):
        by, bx, (u, v) = header_positions[i]
        y0, x0 = by * BLOCK, bx * BLOCK
        block = Y[y0:y0+BLOCK, x0:x0+BLOCK]
        dct = cv2.dct(block)
        bits_read.append(_qim_decode_bit(float(dct[u, v]), DELTA))

    hdr_bytes = _bits_to_bytes(np.array(bits_read, dtype=np.uint8))
    if hdr_bytes[:3] != MAGIC:
        raise ValueError("MAGIC mismatch - no payload found with this password/seed")

    length = struct.unpack(">I", hdr_bytes[3:7])[0]
    coeffs_stored = struct.unpack(">H", hdr_bytes[7:9])[0]

    # compute payload positions using stored coeffs_per_block
    coeffs_used = coeffs_stored if coeffs_per_block is None else coeffs_per_block
    positions_payload = _collect_positions(H, W, coeffs_per_block=coeffs_used, seed=seed)
    # remove header positions to match embedding behavior
    header_set = set(header_positions)
    positions_payload = [p for p in positions_payload if p not in header_set]

    payload_bits_needed = length * 8
    if payload_bits_needed > len(positions_payload):
        raise ValueError("Stego claims more data than capacity")

    bits_read = []
    for i in range(payload_bits_needed):
        by, bx, (u, v) = positions_payload[i]
        y0, x0 = by * BLOCK, bx * BLOCK
        block = Y[y0:y0+BLOCK, x0:x0+BLOCK]
        dct = cv2.dct(block)
        bits_read.append(_qim_decode_bit(float(dct[u, v]), DELTA))

    payload_bytes = _bits_to_bytes(np.array(bits_read, dtype=np.uint8))
    packed = payload_bytes[:length]

    try:
        plain = decrypt_bytes(packed, password)
    except Exception as e:
        raise ValueError("decrypt/auth failed or data corrupted") from e
    return plain.decode("utf-8")

def _read_packed_from_image(stego_path: str, password: str, coeffs_per_block: int = None) -> bytes:
    """
    Read header and return the raw packed payload bytes (salt||nonce||tag||ct)
    without attempting to decrypt. Useful for verification/debugging.
    """
    img = cv2.imread(stego_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Could not read image: {stego_path}")

    Y, Cr, Cb, (H, W) = _to_blocks_y(img)
    seed = _seed_from_password(password)

    header_len_bytes = 3 + 4 + 2
    header_bits_needed = header_len_bytes * 8
    header_positions = _header_positions(H, W)
    if header_bits_needed > len(header_positions):
        raise ValueError("File capacity too small or not stego (header missing)")

    # Read header bits
    bits_read = []
    for i in range(header_bits_needed):
        by, bx, (u, v) = header_positions[i]
        y0, x0 = by * BLOCK, bx * BLOCK
        block = Y[y0:y0+BLOCK, x0:x0+BLOCK]
        dct = cv2.dct(block)
        bits_read.append(_qim_decode_bit(float(dct[u, v]), DELTA))

    hdr_bytes = _bits_to_bytes(np.array(bits_read, dtype=np.uint8))
    if hdr_bytes[:3] != MAGIC:
        raise ValueError("MAGIC mismatch - no payload found with this password/seed")

    length = struct.unpack(">I", hdr_bytes[3:7])[0]
    coeffs_stored = struct.unpack(">H", hdr_bytes[7:9])[0]

    coeffs_used = coeffs_stored if coeffs_per_block is None else coeffs_per_block
    positions_payload = _collect_positions(H, W, coeffs_per_block=coeffs_used, seed=seed)
    header_set = set(header_positions)
    positions_payload = [p for p in positions_payload if p not in header_set]

    payload_bits_needed = length * 8
    if payload_bits_needed > len(positions_payload):
        raise ValueError("Stego claims more data than capacity")

    bits_read = []
    for i in range(payload_bits_needed):
        by, bx, (u, v) = positions_payload[i]
        y0, x0 = by * BLOCK, bx * BLOCK
        block = Y[y0:y0+BLOCK, x0:x0+BLOCK]
        dct = cv2.dct(block)
        bits_read.append(_qim_decode_bit(float(dct[u, v]), DELTA))

    payload_bytes = _bits_to_bytes(np.array(bits_read, dtype=np.uint8))
    return payload_bytes[:length]

# ---------- CLI ----------
if __name__ == "__main__":
    def usage():
        print("Usage:")
        print(" Embed : python3 PNG_Embed.py embed <input.png> <output.png> <message> <password>")
        print(" Extract: python3 PNG_Embed.py extract <input.png> <password>")
        sys.exit(1)

    if len(sys.argv) < 2:
        usage()

    mode = sys.argv[1].lower()
    if mode == "embed":
        if len(sys.argv) < 6:
            usage()
        infile = sys.argv[2]
        outfile = sys.argv[3]
        message = sys.argv[4]
        password = sys.argv[5]
        # coeffs_per_block is now computed automatically; CLI may still accept an override as sixth arg
        coeffs = None
        if len(sys.argv) >= 7:
            coeffs = int(sys.argv[6])
        embed(infile, outfile, message, password, coeffs_per_block=coeffs)

    elif mode == "extract":
        if len(sys.argv) < 4:
            usage()
        infile = sys.argv[2]
        password = sys.argv[3]
        # extract reads coeffs_per_block from embedded header; optional override can be provided as fourth arg
        coeffs = None
        if len(sys.argv) >= 5:
            coeffs = int(sys.argv[4])
        txt = extract(infile, password, coeffs_per_block=coeffs)
        print(json.dumps({"message": f"Recovered plaintext: {txt}"}))

    else:
        print("Mode must be 'embed' or 'extract'")
