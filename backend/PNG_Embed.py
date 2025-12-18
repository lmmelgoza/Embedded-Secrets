
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
# Derive a 32-byte AES key from a password and salt using scrypt.
# Steps:
# 1. Encode the password as UTF-8 bytes.
# 2. Run the scrypt KDF with fixed parameters to obtain a 32-byte key.
def _derive_key(password: str, salt: bytes) -> bytes:
    return scrypt(password.encode("utf-8"), salt, 32, N=2**15, r=8, p=1)

# Encrypt arbitrary bytes with a password using AES-GCM, returning a packed blob.
# Steps:
# 1. Generate a random SALT and NONCE.
# 2. Derive the AES key from the password and SALT.
# 3. Initialize an AES-GCM cipher with the derived key and NONCE.
# 4. Encrypt the plaintext and compute the authentication TAG.
# 5. Concatenate SALT || NONCE || TAG || ciphertext and return it.
def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    # Step 1
    salt = get_random_bytes(SALT_LEN)
    nonce = get_random_bytes(NONCE_LEN)
    # Step 2
    key = _derive_key(password, salt)
    # Step 3
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    # Step 4
    return salt + nonce + tag + ct

# Decrypt bytes produced by encrypt_bytes using the same password.
# Steps:
# 1. Split the packed blob into SALT, NONCE, TAG, and ciphertext.
# 2. Derive the AES key from the password and SALT.
# 3. Initialize AES-GCM and decrypt, verifying the TAG.
# 4. Return the recovered plaintext bytes.
def decrypt_bytes(packed: bytes, password: str) -> bytes:
    # Step 1
    salt = packed[:SALT_LEN]
    nonce = packed[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag = packed[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
    ct = packed[SALT_LEN + NONCE_LEN + TAG_LEN:]
    # Step 2
    key = _derive_key(password, salt)
    # Step 3
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ct, tag)
    # Step 4
    return plain

# Derive a deterministic integer seed from a password.
# Steps:
# 1. Compute SHA-256 over the UTF-8 encoded password.
# 2. Convert the first 8 bytes of the hash to a big-endian integer.
def _seed_from_password(password: str) -> int:
    # Step 1
    h = hashlib.sha256(password.encode("utf-8")).digest()
    # Step 2
    return int.from_bytes(h[:8], "big")

# ---------- Bit helpers ----------
# Convert bytes -> bit array (MSB first per byte) in a version-safe way.
# Steps:
# 1. Allocate an array of zeros to hold 8 bits per byte.
# 2. For each byte, extract bits 7..0 and write them MSB-first into the array.
# 3. Return the resulting uint8 bit array.
def _bytes_to_bits(b: bytes) -> np.ndarray:
    # Step 1
    bits = np.zeros(len(b) * 8, dtype=np.uint8)
    # Step 2
    for i, byte in enumerate(b):
        for j in range(8):
            # MSB first: bit 7 down to 0
            bits[i * 8 + j] = (byte >> (7 - j)) & 1
    # Step 3
    return bits


# Convert a bit array (MSB first per byte) back into bytes.
# Steps:
# 1. Ensure the number of bits is a multiple of 8.
# 2. Group bits into chunks of 8.
# 3. Accumulate each chunk into a byte (MSB-first) and append to the output.
# 4. Return the resulting bytes object.
def _bits_to_bytes(bits: np.ndarray) -> bytes:
    # Step 1
    n = len(bits)
    if n % 8 != 0:
        raise ValueError("Number of bits is not a multiple of 8")
    # Step 2
    out = bytearray(n // 8)
    # Step 3
    for i in range(n // 8):
        val = 0
        base = i * 8
        for j in range(8):
            val = (val << 1) | int(bits[base + j])
        out[i] = val
    # Step 4
    return bytes(out)

# ---------- DCT/QIM helpers ----------

# Embed a single bit into a DCT coefficient using Quantization Index Modulation.
# Steps:
# 1. Quantize the coefficient c by dividing by Δ and taking floor.
# 2. Choose the target center: 0.25·Δ for bit=0, 0.75·Δ for bit=1.
# 3. Return the quantized coefficient q·Δ + center.
def _qim_embed(c: float, bit: int, delta: float) -> float:
    # Step 1
    q = np.floor(c / delta)
    # Step 2
    center = 0.75 * delta if bit else 0.25 * delta
    # Step 3
    return q * delta + center

# Decode a bit from a DCT coefficient embedded with _qim_embed.
# Steps:
# 1. Compute the fractional position of c within its Δ interval.
# 2. If the fraction is closer to 0.75 than 0.25 (i.e. > 0.5), treat as bit 1.
# 3. Otherwise, treat as bit 0.
def _qim_decode_bit(c: float, delta: float) -> int:
    # Step 1
    frac = c / delta - np.floor(c / delta)  # in [0,1)
    # Step 2 and 3
    return 1 if frac > 0.5 else 0
# Convert a BGR image to its Y channel in YCrCb and crop to an 8×8 block grid.
# Steps:
# 1. Convert input BGR image to YCrCb colorspace.
# 2. Extract the Y (luminance) channel and center it around 128.0 for DCT.
# 3. Compute the largest H×W region that is a multiple of BLOCK in both dims.
# 4. Return cropped Y, Cr, Cb planes and (H, W) of the usable block region.
def _to_blocks_y(image_bgr: np.ndarray):
    # Step 1
    ycrcb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2YCrCb)
    # Step 2
    Y = ycrcb[..., 0].astype(np.float32) - 128.0
    # Step 3
    h, w = Y.shape
    H = h - (h % BLOCK)
    W = w - (w % BLOCK)
    # Step 4
    return Y[:H, :W], ycrcb[:H, :W, 1], ycrcb[:H, :W, 2], (H, W)

# Reconstruct a BGR image using an embedded Y channel and original chroma.
# Steps:
# 1. Copy the original BGR image and convert it to YCrCb.
# 2. Replace the Y channel in the usable H×W region with Y_emb + 128.0.
# 3. Restore the original Cr and Cb channels in the same region.
# 4. Convert back to BGR and return the reconstructed image.
def _from_blocks_y(Y_emb: np.ndarray, Cr: np.ndarray, Cb: np.ndarray, original_bgr: np.ndarray, H: int, W: int):
    # Step 1
    out = original_bgr.copy()
    ycrcb = cv2.cvtColor(out, cv2.COLOR_BGR2YCrCb)
    # Step 2
    ycrcb[:H, :W, 0] = np.clip(Y_emb + 128.0, 0, 255).astype(np.uint8)
    # Step 3
    ycrcb[:H, :W, 1] = Cr
    ycrcb[:H, :W, 2] = Cb
    # Step 4
    return cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)

#Build a deterministic, shuffled list of DCT positions for payload embedding.
# Steps:
# 1. Initialize a local PRNG with the given seed.
# 2. Compute the number of 8×8 blocks across the H×W grid.
# 3. Ensure coeffs_per_block does not exceed the number of MID_BAND positions.
# 4. For each block, randomly sample coeffs_per_block mid-band positions.
# 5. Append (by, bx, (u, v)) for each chosen coefficient.
# 6. Shuffle the global list of coordinates and return it.
def _collect_positions(H: int, W: int, coeffs_per_block: int, seed: int):
    import random
    # Step 1
    rng = random.Random(seed)
    # Step 2
    by_max = H // BLOCK
    bx_max = W // BLOCK
    # Step 3
    if coeffs_per_block > len(MID_BAND):
        raise ValueError(f"coeffs_per_block = {coeffs_per_block} exceeds number of available " f"mid-band positions ({len(MID_BAND)}).")

    # Step 4
    coords = []
    for by in range(by_max):
        for bx in range(bx_max):
            uvs = rng.sample(MID_BAND, coeffs_per_block)
            # Step 5
            for uv in uvs:
                coords.append((by, bx, uv))
    # Step 6
    rng.shuffle(coords)
    # Step 7
    return coords

# Return fixed positions for embedding the header, one coeff per block.
# Steps:
# 1. Compute block grid dimensions from H and W.
# 2. For each block in row-major order, select the first MID_BAND coord.
# 3. Append (by, bx, uv) to the header coordinate list.
# 4. Return the full header position list.
def _header_positions(H: int, W: int):
    # Step 1
    coords = []
    by_max = H // BLOCK
    bx_max = W // BLOCK
    uv = MID_BAND[0]
    # Step 2 and 3
    for by in range(by_max):
        for bx in range(bx_max):
            coords.append((by, bx, uv))
    # Step 4
    return coords

# ---------- Core embed/extract ----------
# Embed an encrypted plaintext into a PNG image using DCT/QIM steganography.
# Steps:
# 1. Load the input PNG as a BGR image and convert it to Y blocks.
# 2. Encrypt the UTF-8 plaintext with the password (AES-GCM) to get payload bytes.
# 3. Compute the header size (MAGIC + payload length + coeffs_per_block).
# 4. Count 8×8 blocks and convert the payload to a bit array.
# 5. Derive a deterministic RNG seed from the password.
# 6. Reserve fixed positions for the header and verify capacity.
# 7. Determine coeffs_per_block (either user-supplied or minimal required) and
#    compute payload embedding positions, excluding header positions.
# 8. Build and bit-encode the header (including final coeffs_per_block).
# 9. Embed header bits into the reserved header positions using QIM on DCT coeffs.
# 10. Embed payload bits into the remaining positions using QIM.
# 11. Reconstruct the full BGR image from the modified Y channel and save it.
# 12. Emit JSON metadata and run a verification pass by re-extracting packed bytes;
#     if verification fails, emit diagnostics and raise an error.
def embed(in_path: str, out_path: str, plaintext: str, password: str, coeffs_per_block: int = None):
    # Step 1
    img = cv2.imread(in_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Could not read image: {in_path}")

    Y, Cr, Cb, (H, W) = _to_blocks_y(img)

    # Step 2
    payload_enc = encrypt_bytes(plaintext.encode("utf-8"), password)
    length = len(payload_enc)

    # Step 3
    header_len_bytes = 3 + 4 + 2  # MAGIC(3) + length(4) + coeffs_per_block(2)
    header_bits_needed = header_len_bytes * 8

    # Step 4
    num_blocks = (H // BLOCK) * (W // BLOCK)
    if num_blocks == 0:
        raise ValueError("Image too small for 8x8 DCT blocks")

    # Step 5
    payload_bits = _bytes_to_bits(payload_enc)
    # Step 6
    seed = _seed_from_password(password)

    # Step 7
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

    # Step 8
    header_bytes = MAGIC + struct.pack(">I", length) + struct.pack(">H", coeffs_final)
    header_bits = _bytes_to_bits(header_bytes)

    # informational JSON lines (previously printed human-readable lines)
    print(json.dumps({"seed": seed}))
    print(json.dumps({"num_blocks": int(num_blocks)}))
    print(json.dumps({"header_bytes": int(header_len_bytes)}))
    print(json.dumps({"chosen_coeffs_per_block": int(coeffs_final)}))
    print(json.dumps({"capacity_bits_after_header": int(len(positions_payload))}))
    print(json.dumps({"delta": float(DELTA)}))

    # Step 9
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

    # Step 10
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

    # Step 11
    out_bgr = _from_blocks_y(Yw, Cr, Cb, img, H, W)
    ok = cv2.imwrite(out_path, out_bgr)
    if not ok:
        raise ValueError(f"Failed to write output: {out_path}")

    # Step 12
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

# Extract and decrypt the hidden plaintext from a stego PNG created by embed().
# Steps:
# 1. Load the stego PNG and convert it to the Y channel blocks.
# 2. Derive a deterministic seed from the password.
# 3. Compute header size and fixed header positions, verifying capacity.
# 4. Read and decode header bits (MAGIC, length, coeffs_per_block).
# 5. Validate MAGIC; if it does not match, fail with "no payload".
# 6. Use the stored or override coeffs_per_block to compute payload positions,
#    excluding header positions, and check capacity.
# 7. Read payload bits from the image, convert them to bytes, and trim to length.
# 8. Decrypt the packed payload with the password (AES-GCM).
# 9. Decode the resulting plaintext as UTF-8 and return it.
def extract(stego_path: str, password: str, coeffs_per_block: int = None) -> str:
    # Step 1
    img = cv2.imread(stego_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Could not read image: {stego_path}")

    Y, Cr, Cb, (H, W) = _to_blocks_y(img)
    # Step 2
    seed = _seed_from_password(password)
    # Step 3
    header_len_bytes = 3 + 4 + 2
    header_bits_needed = header_len_bytes * 8

    header_positions = _header_positions(H, W)
    if header_bits_needed > len(header_positions):
        raise ValueError("File capacity too small or not stego (header missing)")

    print(json.dumps({"seed": seed}))
    print(json.dumps({"delta": float(DELTA)}))

    # Step 4
    bits_read = []
    for i in range(header_bits_needed):
        by, bx, (u, v) = header_positions[i]
        y0, x0 = by * BLOCK, bx * BLOCK
        block = Y[y0:y0+BLOCK, x0:x0+BLOCK]
        dct = cv2.dct(block)
        bits_read.append(_qim_decode_bit(float(dct[u, v]), DELTA))

    hdr_bytes = _bits_to_bytes(np.array(bits_read, dtype=np.uint8))
    # Step 5
    if hdr_bytes[:3] != MAGIC:
        raise ValueError("MAGIC mismatch - no payload found with this password/seed")
    # Step 6
    length = struct.unpack(">I", hdr_bytes[3:7])[0]
    coeffs_stored = struct.unpack(">H", hdr_bytes[7:9])[0]

    # compute payload positions using stored coeffs_per_block
    coeffs_used = coeffs_stored if coeffs_per_block is None else coeffs_per_block
    positions_payload = _collect_positions(H, W, coeffs_per_block=coeffs_used, seed=seed)
    # remove header positions to match embedding behavior
    header_set = set(header_positions)
    positions_payload = [p for p in positions_payload if p not in header_set]
    # Step 7
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
    # Step 8
    try:
        plain = decrypt_bytes(packed, password)
    except Exception as e:
        raise ValueError("decrypt/auth failed or data corrupted") from e
    # Step 9
    return plain.decode("utf-8")

# Low-level helper: read the packed payload bytes from a stego image without decrypting them.
# Steps:
# 1. Load the stego PNG and convert it to Y blocks.
# 2. Derive the deterministic seed from the password.
# 3. Read and validate the header (MAGIC, length, coeffs_per_block).
# 4. Compute payload embedding positions (excluding header positions).
# 5. Read the exact number of payload bits from the image.
# 6. Convert bits to bytes and return the prefix of 'length' bytes.
def _read_packed_from_image(stego_path: str, password: str, coeffs_per_block: int = None) -> bytes:
    # Step 1
    img = cv2.imread(stego_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Could not read image: {stego_path}")

    Y, Cr, Cb, (H, W) = _to_blocks_y(img)
    # Step 2
    seed = _seed_from_password(password)
    # Step 3
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
    # Step 4
    length = struct.unpack(">I", hdr_bytes[3:7])[0]
    coeffs_stored = struct.unpack(">H", hdr_bytes[7:9])[0]

    coeffs_used = coeffs_stored if coeffs_per_block is None else coeffs_per_block
    positions_payload = _collect_positions(H, W, coeffs_per_block=coeffs_used, seed=seed)
    header_set = set(header_positions)
    positions_payload = [p for p in positions_payload if p not in header_set]
    # Step 5    
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
    # Step 6
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
