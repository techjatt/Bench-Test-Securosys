# Configuration & Execution Guide: `primus_bench.py`

This guide explains how to configure your environment and execute benchmark tests using the `primus_bench.py` script. The tool allows you to measure the latency and throughput of classic and **Post-Quantum Cryptography (PQC)** algorithms on **Securosys Primus HSM / CloudHSM** architectures.

---

## 1. Environment Configuration

The script relies entirely on the Python standard library (`ctypes`) and requires no `pip` installations. However, you must tell the script where to find your Securosys PKCS#11 library driver and partition password.

### Environment Variables (Recommended)
Setting these environment variables simplifies command execution by omitting the library path and PIN from every command:

#### On Linux / macOS
```bash
export PRIMUS_P11_LIB="/usr/local/primus/lib/libprimusP11.so"
export PRIMUS_P11_PIN="YourPartitionUserPIN"
```

#### On Windows (PowerShell)
```powershell
$env:PRIMUS_P11_LIB="C:\Program Files\Securosys\Primus P11\primusP11.dll"
$env:PRIMUS_P11_PIN="YourPartitionUserPIN"
```

*Alternatively, you can provide these directly in the command arguments using `-lib <path>` and `-pwd <pin>`.*

---

## 2. Command Line Arguments Reference

| Switch | Argument Type | Description |
| :--- | :--- | :--- |
| `-m`, `-mode` | String | Specifies a single cryptographic function to test (e.g., `rsasigver`, `aesenc`). |
| `-suite` | String | Runs a predefined package of multiple tests back-to-back (`classic`, `pqc`, `keygen`, `all`). |
| `-s` / `-ns` | Comma List / Spec | Assigns threads per slot. `-s 0,0` maps 2 threads to slot 0. `-ns 0x8` maps 8 threads to slot 0. |
| `-procs` | Integer | Number of distinct operating system processes to spawn (essential for bypassing the Python GIL). |
| `-t`, `-timed` | Float | Maximum test duration in seconds (defaults to 30 seconds for standalone tests). |
| `-hash` | String | Defines digest algorithms for signature/MAC payloads (`sha256`, `sha384`, `sha512`, `none`, etc.). |
| `-csv` | Filepath | Appends performance data rows automatically to a target text document. |

---

## 3. Practical Execution Examples

### A. Discovery and Pre-Flight Audits
Before running intensive throughput calculations, map out your accessible hardware layout and mechanism configuration:

* **Inventory Available Partitions and Active Sessions:**
  ```bash
  python primus_bench.py -list
  ```
* **Verify Cryptographic Capability Matrix on Slot 0:**
  ```bash
  python primus_bench.py -mechs -s 0
  ```
* **Calculate Baseline Round-Trip Network Latency Only:**
  ```bash
  python primus_bench.py -latency -s 0
  ```

### B. Benchmarking Classic Cryptography
Stressing standard legacy structures with explicit thread distributions:

* **RSA-2048 Digital Signature Generation and Verification:**
  *Configures 8 concurrent workers processing via SHA-256 for a standard 30-second window.*
  ```bash
  python primus_bench.py -m rsasigver -k 2048 -ns 0x8 -t 30
  ```
* **ECDSA P-256 Signature Verification Only:**
  *Omits signing tests (`-nov`) to isolate raw public key verification throughput.*
  ```bash
  python primus_bench.py -m ecdsasigver -c p256 -ns 0x16 -t 30 -nov
  ```
* **High-Throughput Symmetric Bulk Encryption (AES-GCM):**
  *Bypasses the Python GIL by distributing 16 threads across 4 distinct worker processes using 1KB payloads.*
  ```bash
  python primus_bench.py -m aesenc -aesmode gcm -p 1024 -ns 0x16 -procs 4 -t 45
  ```

### C. Benchmarking Post-Quantum Cryptography (PQC)
*Requires Primus PKCS#11 Provider >= 2.6.2 (PKCS#11 v3.2) and HSM firmware >= 3.1.*

* **ML-DSA-65 (FIPS 204 Standard) Signature Performance:**
  ```bash
  python primus_bench.py -m mldsasigver -param 65 -ns 0x8 -t 30
  ```
* **SLH-DSA-128f (FIPS 205 Standard) Fast-Variant Signature Arrays:**
  ```bash
  python primus_bench.py -m slhdsasigver -param sha2-128f -ns 0x4 -t 30
  ```
* **ML-KEM-768 (FIPS 203 Standard) Key Encapsulation/Decapsulation Loops:**
  ```bash
  python primus_bench.py -m mlkemencap -param 768 -ns 0x8 -t 30
  ```

### D. Automated Multi-Test Suite Deployments
To systematically profile your environment across multiple configurations, deploy predefined execution suites. These will run a sequence of tests and generate a combined matrix overview at completion:

* **Evaluate All Post-Quantum Configurations:**
  ```bash
  python primus_bench.py -suite pqc -ns 0x4 -csv pqc_results.csv
  ```
* **Evaluate Key Generation Hardware Performance Cycles:**
  ```bash
  python primus_bench.py -suite keygen -ns 0x2
  ```
* **Direct Comparison (PQC vs. Classic Interoperability Performance):**
  ```bash
  python primus_bench.py -suite pqc-vs-classic -ns 0x8 -procs 2
  ```

---

## 4. Troubleshooting & Housekeeping

### Stuck Objects on the Partition
If a test is forcefully terminated (e.g., sudden hardware disconnect or terminal crash) before the cleanup routine finishes, temporary key artifacts prefixed with `p11bench_` might remain stored inside the HSM storage layer.

Clear out orphaned benchmarking objects from a target slot immediately by running:
```bash
python primus_bench.py -cleanup -s 0
```