Performance Benchmark Script
Course: NWC3373 - Fundamental of Cryptography

Tests encryption/decryption time for RC4-like Stream Cipher and
Custom Feistel Block Cipher on 1 KB, 100 KB, and 1 MB files.
Runs multiple iterations and reports average times.
"""

  import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stream_cipher import rc4_encrypt, rc4_decrypt, generate_key as rc4_generate_key
from block_cipher import feistel_encrypt, feistel_decrypt


@dataclass
class SizeResult:
    """Holds the averaged timing results for a single test-data size."""
    size: int
    rc4_enc: float = 0.0
    rc4_dec: float = 0.0
    feistel_enc: float = 0.0
    feistel_dec: float = 0.0


class CipherBenchmarker:
    """Benchmarks stream-cipher and block-cipher implementations across
    a set of data sizes and reports timing statistics."""

    ITERATIONS = 10

    TEST_SIZES = {
        "1 KB": 1024,
        "100 KB": 100 * 1024,
        "1 MB": 1024 * 1024,
    }

    def __init__(self, iterations: int = ITERATIONS):
        self.iterations = iterations
        self.rc4_key = rc4_generate_key(16)   # 128-bit key
        self.feistel_key = os.urandom(16)     # 128-bit key
        self.results: Dict[str, SizeResult] = {}

    @staticmethod
    def _generate_test_data(size_bytes: int) -> bytes:
        """Generate random test data of the specified size."""
        return os.urandom(size_bytes)

    def _time_operation(self, func: Callable, data: bytes, key: bytes):
        """Run a function multiple times and return (avg_seconds, last_result)."""
        elapsed = []
        result = None
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            result = func(data, key)
            t1 = time.perf_counter()
            elapsed.append(t1 - t0)
        return sum(elapsed) / len(elapsed), result

    def _benchmark_size(self, label: str, size: int) -> SizeResult:
        print(f"--- {label} ({size} bytes) ---")
        data = self._generate_test_data(size)

        rc4_enc_avg, rc4_cipher = self._time_operation(rc4_encrypt, data, self.rc4_key)
        rc4_dec_avg, _ = self._time_operation(rc4_decrypt, rc4_cipher, self.rc4_key)

        feistel_enc_avg, feistel_cipher = self._time_operation(
            feistel_encrypt, data, self.feistel_key
        )
        feistel_dec_avg, _ = self._time_operation(
            feistel_decrypt, feistel_cipher, self.feistel_key
        )

        result = SizeResult(
            size=size,
            rc4_enc=rc4_enc_avg,
            rc4_dec=rc4_dec_avg,
            feistel_enc=feistel_enc_avg,
            feistel_dec=feistel_dec_avg,
        )

        print(f"  RC4-like Stream Cipher:")
        print(f"    Encryption: {result.rc4_enc * 1000:.4f} ms")
        print(f"    Decryption: {result.rc4_dec * 1000:.4f} ms")
        print(f"  Custom Feistel Block Cipher:")
        print(f"    Encryption: {result.feistel_enc * 1000:.4f} ms")
        print(f"    Decryption: {result.feistel_dec * 1000:.4f} ms")
        print()

        return result

    def _print_header(self):
        print("=" * 80)
        print("PERFORMANCE BENCHMARK RESULTS")
        print(f"Iterations per test: {self.iterations}")
        print("=" * 80)
        print()

    def _print_summary_table(self):
        print()
        print("=" * 80)
        print("TABLE: Encryption/Decryption Performance Comparison")
        print("=" * 80)
        print(
            f"{'File Size':<12} {'RC4 Enc (ms)':<16} {'RC4 Dec (ms)':<16} "
            f"{'Feistel Enc (ms)':<18} {'Feistel Dec (ms)':<18}"
        )
        print("-" * 80)
        for label in ["1 KB", "100 KB", "1 MB"]:
            r = self.results[label]
            print(
                f"{label:<12} {r.rc4_enc * 1000:<16.4f} {r.rc4_dec * 1000:<16.4f} "
                f"{r.feistel_enc * 1000:<18.4f} {r.feistel_dec * 1000:<18.4f}"
            )
        print("=" * 80)

    def run(self) -> Dict[str, SizeResult]:
        """Run all performance benchmarks and print tabulated results."""
        self._print_header()

        for label, size in self.TEST_SIZES.items():
            self.results[label] = self._benchmark_size(label, size)

        self._print_summary_table()
        return self.results


def run_benchmarks():
    """Backward-compatible entry point mirroring the original function."""
    return CipherBenchmarker().run()


if __name__ == "__main__":
    results = run_benchmarks()
