Course: NWC3373/NWC3193 — Fundamental of Cryptography
University: Universiti Poly-Tech Malaysia
Semester: 0826

Group Members
Name -	Cipher Implementation
Amirul - Stream Cipher
Adam Masyhur - Custom 8-Round Feistel Block Cipher
Arif - Performance + Security
Haziq - Comparison + Report final

-- Overview --
This repository contains our group project for NWC3373: Fundamental of Cryptography, in which we act as cryptographic consultants for a medium-sized organisation that needs to protect its confidential messages and digital files.
The project covers the full engineering lifecycle for two symmetric ciphers — design, implementation, security evaluation, and performance benchmarking — in order to make an evidence-based recommendation on which algorithm suits secure messaging versus secure file storage.

-- What's Implemented --
	•	Stream Cipher (stream_cipher.py) — A simplified RC4-like stream cipher, including key generation, the Key Scheduling Algorithm (KSA), the Pseudo-Random Generation Algorithm (PRGA), and XOR-based encryption/decryption.
	•	Block Cipher (block_cipher.py) — A custom 8-round Feistel network operating on 64-bit blocks with a 128-bit key, including a purpose-built key schedule, round function (S-Box substitution + bit rotation), PKCS#7 padding, and a built-in correctness self-test.
	•	Performance Benchmark (performance_test.py) — Measures and compares encryption/decryption speed of both ciphers across 1 KB, 100 KB, and 1 MB test files.
