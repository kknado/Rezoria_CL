#!/usr/bin/env python3
import argparse
import secrets
from pathlib import Path

MASK32 = 0xFFFFFFFF


def rotl32(value, shift):
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotl32(state[b] ^ state[c], 7)


def word_le(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


def chacha20_block(key, counter, nonce):
    constants = b"expand 32-byte k"
    state = [
        word_le(constants, 0),
        word_le(constants, 4),
        word_le(constants, 8),
        word_le(constants, 12),
        word_le(key, 0),
        word_le(key, 4),
        word_le(key, 8),
        word_le(key, 12),
        word_le(key, 16),
        word_le(key, 20),
        word_le(key, 24),
        word_le(key, 28),
        counter & MASK32,
        word_le(nonce, 0),
        word_le(nonce, 4),
        word_le(nonce, 8),
    ]
    working = state[:]
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    out = bytearray()
    for original, value in zip(state, working):
        out.extend(((original + value) & MASK32).to_bytes(4, "little"))
    return bytes(out)


def chacha20_xor(data, key, nonce, counter=1):
    output = bytearray()
    offset = 0
    while offset < len(data):
        block = chacha20_block(key, counter, nonce)
        chunk = data[offset:offset + 64]
        output.extend(byte ^ block[index] for index, byte in enumerate(chunk))
        offset += len(chunk)
        counter = (counter + 1) & MASK32
    return bytes(output)


def load_or_create_key(path):
    if path.exists():
        key_hex = path.read_text(encoding="ascii").strip()
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            raise ValueError("Key file must contain 32 bytes / 64 hex characters")
        return key
    key = secrets.token_bytes(32)
    path.write_text(key.hex(), encoding="ascii")
    return key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--key-file", default="RezoriaOS.key")
    args = parser.parse_args()

    source = Path(args.source)
    out = Path(args.out)
    key_path = Path(args.key_file)

    key = load_or_create_key(key_path)
    nonce = secrets.token_bytes(12)
    plaintext = source.read_bytes()
    cipher = chacha20_xor(plaintext, key, nonce)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"RZCL1:{nonce.hex()}:{cipher.hex()}\n", encoding="ascii")

    print(f"Wrote {out}")
    print(f"Key file: {key_path}")


if __name__ == "__main__":
    main()

