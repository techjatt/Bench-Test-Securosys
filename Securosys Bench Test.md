# Primus HSM — PKCS#11 Signing Performance Report

## 1. Objective

Measure how many digital signatures per second a Securosys Primus HSM can
sustain over its PKCS#11 interface, using a full key lifecycle
(generate → sign N times → delete) as the test unit.

## 2. Test tool

`pkcs11_sign_bench.py` (included alongside this report). It:

1. Loads the Primus PKCS#11 library and opens one or more sessions.
2. Generates a fresh session (non‑persistent) RSA or EC key pair on the HSM.
3. Runs a short unmeasured warm-up, then signs a fixed test payload
   repeatedly, timing each `C_Sign` call.
4. Repeats step 2–3 concurrently across `--threads` sessions to model
   multiple simultaneous clients — the way the HSM is actually used in
   production and the only way to reach its rated throughput, since a
   single PKCS#11 session serializes its own operations.
5. Destroys the key pair (`C_DestroyObject`) and logs out.
6. Prints throughput (signatures/second) and per-signature latency
   percentiles, and optionally dumps raw timings to CSV.

### Usage

```bash
pip install PyKCS11 --break-system-packages

# Baseline latency: 1 session, RSA-2048, 2000 signatures
python3 pkcs11_sign_bench.py \
  --lib /opt/securosys/primus/lib/libprimusP11.so \
  --pin <PIN> --key-type rsa2048 --iterations 2000

# Throughput sweep: 16 concurrent sessions, EC P-256, 30s run
python3 pkcs11_sign_bench.py \
  --lib /opt/securosys/primus/lib/libprimusP11.so \
  --pin <PIN> --key-type ecp256 --threads 16 --duration 30 --csv run16.csv
```

Key parameters:

| Flag | Purpose |
|---|---|
| `--key-type` | `rsa2048`, `rsa3072`, `rsa4096`, `ecp256`, `ecp384` |
| `--threads` | Concurrent PKCS#11 sessions (models concurrent clients) |
| `--iterations` / `--duration` | Fixed op count per session, or a fixed wall-clock run |
| `--csv` | Write every individual signature's latency for later analysis |

## 3. Recommended test procedure

1. **Connectivity/latency baseline** — `--threads 1`, ~500–2000 iterations,
   for RSA‑2048, RSA‑4096, and EC P‑256. This gives the single-operation
   round-trip latency (network/driver overhead + HSM crypto time).
2. **Concurrency sweep** — repeat with `--threads` at 1, 2, 4, 8, 16, 32, 64,
   holding key type and payload fixed, `--duration 20` each. Plot
   throughput vs. thread count. Throughput rises with concurrency until the
   HSM's internal crypto engines / network stack saturate, then flattens —
   that plateau is the sustained signatures/second figure for that key type.
3. **Repeat per key type**, since RSA-4096 is materially more expensive than
   RSA-2048 or EC P-256/P-384 on virtually all HSMs.
4. **Sanity-check errors**: any `err_count > 0` in the summary usually
   indicates session/slot exhaustion, PIN/permission issues, or the HSM
   throttling — worth noting alongside the throughput number rather than
   averaging it away.

## 4. Results

> **This run.** This benchmark could not be executed against a physical
> Primus HSM in this environment (no network access / no HSM or PKCS#11
> library available here). The table below therefore has two parts:
> vendor-published reference figures for context, and a blank template to
> fill in with your own measurements from `pkcs11_sign_bench.py` against
> your specific Primus unit, firmware version, and network path — actual
> numbers depend heavily on the model, partitioning, connection type
> (local PCIe/USB vs. network appliance), and client concurrency.

### 4.1 Vendor-published reference figures (for context only, not measured here)

| Model / class | Published figure | Source |
|---|---|---|
| Primus HSM X-Series | Over 1,000 RSA-4096 signatures per second; manages over 4 million key pairs across 120 partitions | Securosys product launch announcement |
| Primus HSM (general, CNG API) | Up to 4,000 RSA-2048 signings/second per HSM | Securosys Microsoft PKI solution brief |
| Primus X Cyber Vault (X2) | Over 50,000 transactions per second single-unit; scales to over 1,000,000 TPS clustered | Securosys HSM overview page |

These are vendor figures for specific models/mechanisms (note the CNG figure
is a different API path than PKCS#11, and TPS figures for the Cyber Vault
line cover mixed transaction types, not RSA-4096 signing alone). Treat them
as an order-of-magnitude expectation, not a substitute for measuring your
own deployment.

### 4.2 Measured results — template to fill in

| Key type | Threads | Iterations/duration | Signatures/sec | p50 latency (ms) | p95 latency (ms) | p99 latency (ms) | Errors |
|---|---|---|---|---|---|---|---|
| rsa2048 | 1  | 2000 | | | | | |
| rsa2048 | 8  | 20s  | | | | | |
| rsa2048 | 32 | 20s  | | | | | |
| rsa4096 | 1  | 2000 | | | | | |
| rsa4096 | 32 | 20s  | | | | | |
| ecp256  | 1  | 2000 | | | | | |
| ecp256  | 32 | 20s  | | | | | |

Run the commands in section 2/3 against your Primus unit and paste the
console summary (or the CSV-derived percentiles) into this table.

## 5. Interpreting the numbers

- **Single-session latency** tells you the per-call round trip (useful for
  understanding worst-case latency for a single synchronous caller, e.g. a
  CA signing one certificate).
- **Throughput under concurrency** tells you the number that matters for
  capacity planning (e.g. "can this HSM keep up with our TLS handshake
  rate / blockchain signing rate"). Increase `--threads` until throughput
  stops increasing — that plateau, not the single-thread number, is the
  HSM's real signatures/second capability for that key type.
- **RSA vs. EC**: EC (P‑256/P‑384) signing is computationally far cheaper
  than RSA and will typically show noticeably higher signatures/second and
  lower latency on the same hardware.
- **Network vs. local**: if the Primus unit is accessed as a network
  appliance (vs. local PCIe/USB), round-trip network latency adds directly
  to single-thread latency but is amortized away at higher concurrency.

## 6. Caveats

- Numbers are highly dependent on: Primus model/tier, firmware version,
  number of active partitions, network path (local vs. remote, and via
  Decanus if used), TLS session reuse, and whether other workloads are
  sharing the same HSM/partition concurrently.
- This script uses `CKM_SHA256_RSA_PKCS` / `CKM_ECDSA_SHA256` (hash‑and‑sign
  of a fixed short payload) so the timing reflects the HSM's per‑operation
  crypto + protocol cost, not hashing of large payloads.
- Keys are generated as PKCS#11 **session objects** (`CKA_TOKEN=False`), so
  they are never persisted to the HSM's key store and are also cleaned up
  automatically on logout even if `C_DestroyObject` is skipped; the script
  still calls it explicitly to demonstrate/exercise the full lifecycle.
