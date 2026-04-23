# 🔐 Entropic XOR Compressor

A C++ experiment in hardware-entropy-driven random bit generation and recursive XOR-based binary compression.

---

## 💡 The Idea

This project combines two interesting concepts:

1. **True Random Number Generation** via CPU timing jitter — harvesting entropy from real hardware noise rather than a deterministic PRNG.
2. **Recursive XOR Compression** — a novel scheme that reduces a binary string layer-by-layer down to a single bit, storing the keys and XOR residuals needed to fully reconstruct the original.

---

## 🧩 Components

### `SystemClock`
A lightweight wrapper around `std::chrono::system_clock` that exposes the current time at various resolutions (seconds, milliseconds, microseconds, **nanoseconds**).

---

### `CRYPTO::SHA256`
A self-contained, dependency-free SHA-256 implementation. Used to whiten and compress raw entropy bits into high-quality pseudorandom output. Supports:
- `update(data)` — feed bytes or strings
- `digest()` — returns a 64-character hex hash
- `digestBinary()` — returns a 256-character binary string (`0`/`1`)

---

### `RandomNumberGenerator`
The core entropy harvester. It works by:
1. Timing a tiny CPU loop (`countdown()`) in nanoseconds
2. Comparing each measurement against a running average to assign a `0` or `1` bit
3. Accumulating bits into a 512-bit sliding window
4. Hashing each window with SHA-256 to produce a whitened 256-bit output

> The randomness comes from real, unpredictable CPU timing variance — not a seed.

---

### `BinaryEntropyPool`
A thread-safe pool that buffers entropy bit strings. It lazily refills itself by calling `RandomNumberGenerator::run()` whenever more bits are needed, then hands out exactly the requested number of bits.

---

### `XORCompress`
The star of the show. Given a binary string of length *2ⁿ*, it recursively halves it:

```
For each pair (A, B):
    XOR result  = A XOR B
    Key         = A
```

The **key** becomes the input to the next layer. The **XOR result** is stored as a residual. This repeats until only a single bit remains.

**Decompression** replays the layers in reverse, reconstructing each pair from its key and XOR residual.

Also includes helpers to convert arbitrary strings ↔ binary ASCII for compressing text.

---

## 🚀 Usage

```bash
g++ -std=c++17 -O2 -o program main.cpp
./program
```

The program will:
1. Generate 64 entropy bits from hardware timing jitter
2. Compress them recursively with XORCompress
3. Print each layer's keys and XOR residuals
4. Decompress and verify the round-trip

---

## 📋 Example Output

```
bitstream:  1011001101110010...  (64 bits)

Compressing...
Final bit: 1
Layers: 6

Keys:
Layer 0: 10110011...
Layer 1: 11001011...
...

Restored: 1011001101110010...
SUCCESS: data restored correctly
```

---

## 🔬 Notes & Observations

- This is **not a traditional compression algorithm** — the stored keys + XOR residuals together are larger than the original input. Think of it more as a **lossless decomposition tree**.
- The entropy source is platform-dependent; timing jitter quality varies by CPU, OS scheduler, and load.
- SHA-256 whitening ensures the output bit distribution is uniform regardless of raw jitter quality.
- The commented-out Genesis 1:1–3 passage in `main()` is a fun test vector for the text compression path. 😄

---

## 🛠️ Potential Extensions

- Stream the entropy pool from a background thread for better throughput
- Benchmark bit bias and run NIST randomness tests on the output
- Explore using the XOR tree structure as a Merkle-like integrity scheme
- Visualize the compression layers as a binary tree

---

Oiko Nomikos
