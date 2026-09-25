Simplified RC4-like Stream Cipher
Author: Amirul Hakim
Course: NWC3373 - Fundamental of Cryptography

Implements: Key Generation, KSA, PRGA, XOR Encryption/Decryption
"""

import os


class RC4Cipher:
    """Encapsulates the RC4-like stream cipher: key scheduling, keystream
    generation, and XOR-based encryption/decryption."""

    STATE_SIZE = 256

    def __init__(self, key: bytes):
        self.key = key

    @staticmethod
    def generate_key(key_size_bytes: int = 16) -> bytes:
        """Generates a cryptographically secure random key using OS CSPRNG."""
        return os.urandom(key_size_bytes)

    def _ksa(self) -> list:
        """Key Scheduling Algorithm: initialises and scrambles the
        256-byte permutation array S."""
        key_length = len(self.key)
        S = list(range(self.STATE_SIZE))
        j = 0
        for i in range(self.STATE_SIZE):
            j = (j + S[i] + self.key[i % key_length]) % self.STATE_SIZE
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def _prga(S: list, length: int) -> bytes:
        """Pseudo-Random Generation Algorithm: produces the keystream
        one byte at a time."""
        S = S.copy()  # Don't mutate the original state
        i = 0
        j = 0
        keystream = bytearray()
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            keystream.append(k)
        return bytes(keystream)

    def _keystream(self, length: int) -> bytes:
        """Runs the KSA then PRGA to produce a keystream of the given length."""
        S = self._ksa()
        return self._prga(S, length)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext using RC4 keystream XOR."""
        keystream = self._keystream(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, keystream))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts ciphertext using RC4 keystream XOR (identical to encryption)."""
        keystream = self._keystream(len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))


# --- Module-level function wrappers (kept for backward-compatible imports) ---

def generate_key(key_size_bytes: int = 16) -> bytes:
    """Generates a cryptographically secure random key using OS CSPRNG."""
    return RC4Cipher.generate_key(key_size_bytes)


def ksa(key: bytes) -> list:
    """Key Scheduling Algorithm: initialises and scrambles the 256-byte permutation array S."""
    return RC4Cipher(key)._ksa()


def prga(S: list, length: int) -> bytes:
    """Pseudo-Random Generation Algorithm: produces the keystream one byte at a time."""
    return RC4Cipher._prga(S, length)


def rc4_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts plaintext using RC4 keystream XOR."""
    return RC4Cipher(key).encrypt(plaintext)


def rc4_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts ciphertext using RC4 keystream XOR (identical to encryption)."""
    return RC4Cipher(key).decrypt(ciphertext)


class StreamCipherSelfTest:
    """Runs a simple round-trip verification of the RC4Cipher implementation."""

    MESSAGE = b"Welcome to the NWC3373 Group Project 2026!"

    @classmethod
    def run(cls):
        key = RC4Cipher.generate_key(16)
        cipher = RC4Cipher(key)

        print("Starting Stream Cipher Verification Test...")
        ciphertext = cipher.encrypt(cls.MESSAGE)
        recovered_plaintext = cipher.decrypt(ciphertext)

        assert cls.MESSAGE == recovered_plaintext, \
            "ERROR: Decryption output does not match the original input!"
        print("Verification Successful: RC4-like stream cipher encryption and decryption are working perfectly.")


if __name__ == "__main__":
    # Self-Verification Guard
    StreamCipherSelfTest.run()
