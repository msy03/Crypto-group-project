"""
Custom 8-Round Feistel Block Cipher
====================================
NWC3373 - Fundamental of Cryptography - Part A2
Author: Muhammad Adam Masyhur bin Mohd Nasir
"""

import struct
import os

ROUNDS = 8          # assignment requires minimum 8 rounds
BLOCK_SIZE = 8       # bytes = 64-bit block
KEY_SIZE = 16         # bytes = 128-bit key

def build_sbox():
    sbox = []
    for x in range(256):
        val = (x * x + 47 * x + 91) % 256
        sbox.append(val)
    return sbox

S_BOX = build_sbox()

def generate_subkeys(master_key: bytes) -> list:
    """Takes the 128-bit master key and produces one subkey per round."""
    if len(master_key) < KEY_SIZE:
        master_key = master_key.ljust(KEY_SIZE, b'\x00')

    w0, w1, w2, w3 = struct.unpack("!4I", master_key[:KEY_SIZE])

    subkeys = []
    for r in range(ROUNDS):

        w0 = ((w0 << 3)  | (w0 >> 29)) & 0xFFFFFFFF
        w1 = ((w1 << 7)  | (w1 >> 25)) & 0xFFFFFFFF
        w2 = ((w2 << 11) | (w2 >> 21)) & 0xFFFFFFFF
        w3 = (w3 + 0x61C88647 + r) & 0xFFFFFFFF   

        subkey = (w0 ^ w1 ^ w2 ^ w3) & 0xFFFFFFFF
        subkeys.append(subkey)

        w0, w1, w2, w3 = w1, w2, w3, w0

    return subkeys

def round_function(half_block: int, subkey: int) -> int:
    mixed = half_block ^ subkey

    b0 = S_BOX[(mixed >> 24) & 0xFF]
    b1 = S_BOX[(mixed >> 16) & 0xFF]
    b2 = S_BOX[(mixed >> 8)  & 0xFF]
    b3 = S_BOX[mixed & 0xFF]
    substituted = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    rotated = ((substituted << 13) | (substituted >> 19)) & 0xFFFFFFFF

    return rotated ^ subkey

def encrypt_block(block: bytes, subkeys: list) -> bytes:
    L, R = struct.unpack("!2I", block)
    for i in range(ROUNDS):
        L, R = R, L ^ round_function(R, subkeys[i])
    return struct.pack("!2I", L, R)


def decrypt_block(block: bytes, subkeys: list) -> bytes:
    L, R = struct.unpack("!2I", block)
    for i in reversed(range(ROUNDS)):
        L, R = R ^ round_function(L, subkeys[i]), L
    return struct.pack("!2I", L, R)


def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    subkeys = generate_subkeys(key)
    data = pad(plaintext)
    ciphertext = b""
    for i in range(0, len(data), BLOCK_SIZE):
        ciphertext += encrypt_block(data[i:i + BLOCK_SIZE], subkeys)
    return ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    subkeys = generate_subkeys(key)
    plaintext = b""
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        plaintext += decrypt_block(ciphertext[i:i + BLOCK_SIZE], subkeys)
    return unpad(plaintext)


def generate_key(key_size_bytes: int = KEY_SIZE) -> bytes:
    return os.urandom(key_size_bytes)


if __name__ == "__main__":
    key = generate_key()
    message = b"This message proves our Feistel cipher works correctly!"

    ciphertext = encrypt(message, key)
    recovered = decrypt(ciphertext, key)

    print("Original :", message)
    print("Encrypted:", ciphertext.hex())
    print("Decrypted:", recovered)
    print("\nCorrectness check passed:", recovered == message)
