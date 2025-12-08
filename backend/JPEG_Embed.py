#!/usr/bin/env python3

import struct
import hashlib
import numpy as np
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import jpegio as jio
import json

MAGIC = b'JH1'
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16

BOUNDARIES = {1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047}

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
# a deterministic seed derived from password so that extraction only requires password
def _seed_from_password(password: str) -> int:
    h = hashlib.sha256(password.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big")

# bit helpers
def _bytes_to_bits(b: bytes) -> np.ndarray:
    arr = np.frombuffer(b, dtype=np.uint8)
    return np.unpackbits(arr)

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Number of bits is not a multiple of 8")
    packed = np.packbits(bits)
    return packed.tobytes()

def _collect_positions(jpeg, seed: int):
    import random
    rng = random.Random(seed)
    positions = []
    for comp_idx, coef_array in enumerate(jpeg.coef_arrays):
        h_blocks = coef_array.shape[0] // 8
        w_blocks = coef_array.shape[1] // 8
        for by in range(h_blocks):
            for bx in range(w_blocks):
                block = coef_array[by*8:(by+1)*8, bx*8:(bx+1)*8]
                flat = block.flatten()
                for k in range(1, 64):
                    v = int(flat[k])
                    if v == 0:
                        continue
                    # only use coefficients that can represent BOTH parity bits
                    if _set_parity_preserve_category(v, 0) is None:
                        continue
                    if _set_parity_preserve_category(v, 1) is None:
                        continue
                    positions.append((comp_idx, by, bx, k))
    rng.shuffle(positions)
    return positions

def _set_parity_preserve_category(val: int, bit: int):
    if val == 0:
        return None
    
    sign = -1 if val < 0 else 1
    a = abs(val)

    if (a & 1) == bit:
        return sign * a
    
    s= a.bit_length()
    lower = 1 << (s-1)
    upper = (1 << s) - 1

    if a > lower:
        return sign * (a - 1)
    if a < upper:
        return sign * (a + 1)
    return None

def embed(in_jpeg_path: str, out_jpeg_path: str, plaintext: str, password: str):
    jpeg = jio.read(in_jpeg_path)
    payload_enc = encrypt_bytes(plaintext.encode("utf-8"), password)
    length = len(payload_enc)
    header = MAGIC + struct.pack(">I", length)
    full = header + payload_enc
    bits = _bytes_to_bits(full)

    seed = _seed_from_password(password)
    positions = _collect_positions(jpeg, seed)

    if bits.size > len(positions):
        raise ValueError(f"Payload too large to embed in the given JPEG image: need {bits.size} bits, capacity {len(positions)}.")
    
    #print("SEED:", _seed_from_password(password))
    #print("CAPACITY:", len(_collect_positions(jpeg, _seed_from_password(password))))
    capacity = len(positions)

    idx = 0
    written = 0
    while written < bits.size and idx < len(positions):
        comp_idx, by, bx, k = positions[idx]
        idx += 1
        block = jpeg.coef_arrays[comp_idx][by*8:(by+1)*8, bx*8:(bx+1)*8]
        flat = block.flatten()
        v = int(flat[k])
        new_v = _set_parity_preserve_category(v, bits[written])
        if new_v is None:
            continue
        flat[k] = new_v
        jpeg.coef_arrays[comp_idx][by*8:(by+1)*8, bx*8:(bx+1)*8] = flat.reshape(8, 8)
        written += 1

    if written < bits.size:
        raise ValueError(f"Not enough safe coefficients (wrote {written}/{bits.size} bits).")


    jio.write(jpeg, out_jpeg_path)
    #print(f"Embedded {len(plaintext)} bytes (ciphertext {length} bytes) into {out_jpeg_path}")

    return {
        "input_path": in_jpeg_path,
        "output_path": out_jpeg_path,
        "bytes_embedded": len(plaintext),
        "ciphertext_bytes": length,
    }

def extract(stego_jpeg_path: str, password: str) -> str:
    jpeg = jio.read(stego_jpeg_path)
    seed = _seed_from_password(password)
    positions = _collect_positions(jpeg, seed)

    #print("SEED:", _seed_from_password(password))
    #print("CAPACITY:", len(_collect_positions(jpeg, _seed_from_password(password))))


    header_bits_needed = 7 * 8
    if header_bits_needed > len(positions):
        raise ValueError("file capacity to small or not stego")
    
    hdr_bits = []
    for i in range(header_bits_needed):
        comp_idx, by, bx, k = positions[i]
        val = int(jpeg.coef_arrays[comp_idx][by*8:(by+1)*8, bx*8:(bx+1)*8].flatten()[k])
        hdr_bits.append(abs(val) & 1)
    hdr_bytes = _bits_to_bytes(np.array(hdr_bits, dtype=np.uint8))
    if hdr_bytes[:3] != MAGIC:
        raise ValueError("MAGIC mismatch - no payload found with this password/seed")
    
    length = struct.unpack(">I", hdr_bytes[3:7])[0]
    total_bits = (7 + length) * 8
    if total_bits > len(positions):
        raise ValueError("stego claims more data than capacity")
    
    all_bits = []
    for i in range(total_bits):
        comp_idx, by, bx, k = positions[i]
        val = int(jpeg.coef_arrays[comp_idx][by*8:(by+1)*8, bx*8:(bx+1)*8].flatten()[k])
        all_bits.append(abs(val) & 1)
    all_bytes = _bits_to_bytes(np.array(all_bits, dtype=np.uint8))
    packed = all_bytes[7:]

    try:
        plain = decrypt_bytes(packed[:length], password)
    except Exception as e:
        raise ValueError("decrypt/auth failed or data corrupted") from e
    return plain.decode("utf-8")

if __name__ == "__main__":
    import sys
    
    def usage():
        print("Usage:")
        print(" Embed: python3 JPEG_Embed.py embed <input.jpg> <output.jpg> <message> <password>")
        print(" Extract: python3 JPEG_Embed.py extract <input.jpg> <password>")
        sys.exit(1)

    if len(sys.argv) < 2:
        usage()

    mode = sys.argv[1].lower()
    # Check if the mode is valid
    if mode == "embed":
        if len(sys.argv) < 6:
            usage()
        infile = sys.argv[2]
        outfile = sys.argv[3]
        message = sys.argv[4]
        password = sys.argv[5]
        result = embed(infile, outfile, message, password)
        print(json.dumps({"input_path": result["input_path"]}))
        print(json.dumps({"output_path": result["output_path"]}))
        print(json.dumps({"bytes_embedded": result["bytes_embedded"]}))

    elif mode == "extract":
        if len(sys.argv) < 4:
            usage()
        infile = sys.argv[2]
        password = sys.argv[3]
        txt = extract(infile, password)
        print(json.dumps({"message": f"Recovered plaintext: {txt}"}))

    else:
        print("Mode must be 'embed' or 'extract'")