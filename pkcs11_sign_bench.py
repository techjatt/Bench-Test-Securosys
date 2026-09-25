#!/usr/bin/env python3
"""
pkcs11_sign_bench.py
=====================

Performance test for signing operations on a Securosys Primus HSM (or any
PKCS#11-compliant HSM/token) via the PKCS#11 API.

What it does, in order:
  1. Loads the vendor PKCS#11 library (Primus PKCS#11 .so/.dll) and opens a
     session on a chosen slot.
  2. Logs in as the CKU_USER (or CKU_SO, if requested) with the token PIN.
  3. Generates a fresh asymmetric key pair on the HSM (RSA-2048/3072/4096 or
     EC P-256/P-384).
  4. Runs a short warm-up, then benchmarks repeated Sign operations, either
     from a single session (baseline latency) or from N concurrent sessions/
     threads (throughput under concurrency -- the realistic way to find an
     HSM's max signatures/second, since a single session is normally
     serialized).
  5. Deletes the key pair (C_DestroyObject) and logs out / closes sessions.
  6. Prints a summary (throughput, latency percentiles) and optionally writes
     the raw per-signature timings to a CSV file.

Dependencies:
  pip install PyKCS11

Requires:
  - The Primus PKCS#11 shared library (e.g. libprimusP11.so on Linux,
    primusP11.dll on Windows), reachable via --lib or the PKCS11_LIB env var.
  - A configured slot/token and its PIN.

Example usage:
  # Baseline: single session, RSA-2048, 2000 signatures
  python3 pkcs11_sign_bench.py --lib /opt/securosys/primus/lib/libprimusP11.so \\
      --pin 123456 --key-type rsa2048 --iterations 2000

  # Throughput: 16 concurrent sessions, EC P-256, 30 second run
  python3 pkcs11_sign_bench.py --lib /opt/securosys/primus/lib/libprimusP11.so \\
      --pin 123456 --key-type ecp256 --threads 16 --duration 30

Notes:
  - This script is transport-agnostic: it will run identically against a
    Primus HSM, a Primus HSM cluster endpoint, or (for dry-run / dev-testing
    of the script itself) SoftHSM2, since all speak PKCS#11.
  - No key material or PIN is printed or logged.
"""

import argparse
import csv
import os
import statistics
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field

try:
    import PyKCS11
    from PyKCS11 import CKA, CKM, CKO, CKK, CKU
except ImportError:
    sys.exit(
        "ERROR: PyKCS11 is required. Install it with:\n"
        "    pip install PyKCS11 --break-system-packages\n"
    )


# --------------------------------------------------------------------------
# Key-type -> PKCS#11 mechanism / attribute mapping
# --------------------------------------------------------------------------

KEY_TYPES = {
    "rsa2048": {"kind": "rsa", "bits": 2048, "sign_mech": PyKCS11.Mechanism(CKM.SHA256_RSA_PKCS)},
    "rsa3072": {"kind": "rsa", "bits": 3072, "sign_mech": PyKCS11.Mechanism(CKM.SHA256_RSA_PKCS)},
    "rsa4096": {"kind": "rsa", "bits": 4096, "sign_mech": PyKCS11.Mechanism(CKM.SHA256_RSA_PKCS)},
    "ecp256": {"kind": "ec", "curve_oid": "06082A8648CE3D030107", "sign_mech": PyKCS11.Mechanism(CKM.ECDSA_SHA256)},
    "ecp384": {"kind": "ec", "curve_oid": "06052B81040022", "sign_mech": PyKCS11.Mechanism(CKM.ECDSA_SHA384)},
}

MESSAGE_TO_SIGN = b"pkcs11-perf-test-payload-" + os.urandom(16)


@dataclass
class ThreadResult:
    thread_id: int
    ok_count: int = 0
    err_count: int = 0
    latencies_s: list = field(default_factory=list)
    first_error: str = ""


# --------------------------------------------------------------------------
# PKCS#11 session helpers
# --------------------------------------------------------------------------

def open_session(pkcs11, slot, pin, so_login=False):
    session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    session.login(pin, user_type=CKU.SO if so_login else CKU.USER)
    return session


def pick_slot(pkcs11, requested_slot):
    if requested_slot is not None:
        return requested_slot
    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        sys.exit("ERROR: no slot with a token present was found. Pass --slot explicitly.")
    return slots[0]


def generate_keypair(session, key_type_cfg, label):
    """Generates a session (non-persistent) key pair on the HSM and returns (pub, priv) handles."""
    if key_type_cfg["kind"] == "rsa":
        pub_template = [
            (CKA.CLASS, CKO.PUBLIC_KEY),
            (CKA.KEY_TYPE, CKK.RSA),
            (CKA.TOKEN, False),          # session object: vanishes on logout even if delete is skipped
            (CKA.MODULUS_BITS, key_type_cfg["bits"]),
            (CKA.PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (CKA.ENCRYPT, True),
            (CKA.VERIFY, True),
            (CKA.WRAP, False),
            (CKA.LABEL, label),
        ]
        priv_template = [
            (CKA.CLASS, CKO.PRIVATE_KEY),
            (CKA.KEY_TYPE, CKK.RSA),
            (CKA.TOKEN, False),
            (CKA.PRIVATE, True),
            (CKA.SENSITIVE, True),
            (CKA.EXTRACTABLE, False),
            (CKA.SIGN, True),
            (CKA.DECRYPT, False),
            (CKA.UNWRAP, False),
            (CKA.LABEL, label),
        ]
        mech = PyKCS11.Mechanism(CKM.RSA_PKCS_KEY_PAIR_GEN)
    else:  # ec
        pub_template = [
            (CKA.CLASS, CKO.PUBLIC_KEY),
            (CKA.KEY_TYPE, CKK.EC),
            (CKA.TOKEN, False),
            (CKA.EC_PARAMS, bytes.fromhex(key_type_cfg["curve_oid"])),
            (CKA.VERIFY, True),
            (CKA.LABEL, label),
        ]
        priv_template = [
            (CKA.CLASS, CKO.PRIVATE_KEY),
            (CKA.KEY_TYPE, CKK.EC),
            (CKA.TOKEN, False),
            (CKA.PRIVATE, True),
            (CKA.SENSITIVE, True),
            (CKA.EXTRACTABLE, False),
            (CKA.SIGN, True),
            (CKA.LABEL, label),
        ]
        mech = PyKCS11.Mechanism(CKM.EC_KEY_PAIR_GEN)

    pub, priv = session.generateKeyPair(pub_template, priv_template, mecha=mech)
    return pub, priv


def destroy_keypair(session, pub, priv):
    for handle in (pub, priv):
        try:
            session.destroyObject(handle)
        except PyKCS11.PyKCS11Error:
            pass  # already gone (e.g. session objects can vanish on logout)


# --------------------------------------------------------------------------
# Benchmark worker
# --------------------------------------------------------------------------

def worker(thread_id, lib_path, slot, pin, key_type_cfg, iterations, duration, stop_event, result: ThreadResult):
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib_path)
    session = None
    pub = priv = None
    try:
        session = open_session(pkcs11, slot, pin)
        pub, priv = generate_keypair(session, key_type_cfg, label=f"bench-{uuid.uuid4().hex[:8]}")
        mech = key_type_cfg["sign_mech"]

        # Warm-up (not measured): lets the HSM/driver settle (TLS/session caches, etc.)
        for _ in range(min(5, max(iterations // 20, 1))):
            session.sign(priv, MESSAGE_TO_SIGN, mech)

        count = 0
        deadline = time.perf_counter() + duration if duration else None
        while True:
            if deadline is not None:
                if time.perf_counter() >= deadline or stop_event.is_set():
                    break
            else:
                if count >= iterations:
                    break
            t0 = time.perf_counter()
            try:
                session.sign(priv, MESSAGE_TO_SIGN, mech)
                result.latencies_s.append(time.perf_counter() - t0)
                result.ok_count += 1
            except PyKCS11.PyKCS11Error as e:
                result.err_count += 1
                if not result.first_error:
                    result.first_error = str(e)
            count += 1
    except PyKCS11.PyKCS11Error as e:
        result.first_error = result.first_error or str(e)
    finally:
        try:
            if session and pub and priv:
                destroy_keypair(session, pub, priv)
            if session:
                session.logout()
                session.closeSession()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def pct(sorted_vals, p):
    if not sorted_vals:
        return float("nan")
    k = min(len(sorted_vals) - 1, int(round(p / 100 * (len(sorted_vals) - 1))))
    return sorted_vals[k]


def print_summary(results, wall_time_s, key_type, threads):
    all_latencies = sorted(l for r in results for l in r.latencies_s)
    total_ok = sum(r.ok_count for r in results)
    total_err = sum(r.err_count for r in results)
    throughput = total_ok / wall_time_s if wall_time_s > 0 else 0.0

    print("\n" + "=" * 60)
    print(" PRIMUS HSM PKCS#11 SIGNING BENCHMARK — SUMMARY")
    print("=" * 60)
    print(f" Key type:              {key_type}")
    print(f" Concurrent sessions:   {threads}")
    print(f" Wall-clock duration:   {wall_time_s:.2f} s")
    print(f" Successful signatures: {total_ok}")
    print(f" Failed signatures:     {total_err}")
    print(f" Throughput:            {throughput:.1f} signatures/second")
    if all_latencies:
        print(f" Latency (per-op, single session queue time):")
        print(f"   min:    {min(all_latencies)*1000:.2f} ms")
        print(f"   mean:   {statistics.mean(all_latencies)*1000:.2f} ms")
        print(f"   median: {statistics.median(all_latencies)*1000:.2f} ms")
        print(f"   p95:    {pct(all_latencies, 95)*1000:.2f} ms")
        print(f"   p99:    {pct(all_latencies, 99)*1000:.2f} ms")
        print(f"   max:    {max(all_latencies)*1000:.2f} ms")
    for r in results:
        if r.first_error:
            print(f" [thread {r.thread_id}] first error: {r.first_error}")
    print("=" * 60)
    return throughput, total_ok, total_err, all_latencies


def write_csv(path, results):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["thread_id", "op_index", "latency_ms"])
        for r in results:
            for i, lat in enumerate(r.latencies_s):
                w.writerow([r.thread_id, i, f"{lat * 1000:.4f}"])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="PKCS#11 signing performance benchmark for Primus HSM")
    ap.add_argument("--lib", default=os.environ.get("PKCS11_LIB"),
                     help="Path to the PKCS#11 shared library (or set PKCS11_LIB)")
    ap.add_argument("--pin", default=os.environ.get("PKCS11_PIN"),
                     help="User PIN for the token (or set PKCS11_PIN)")
    ap.add_argument("--slot", type=int, default=None, help="Slot ID to use (default: first slot with a token)")
    ap.add_argument("--key-type", choices=KEY_TYPES.keys(), default="rsa2048")
    ap.add_argument("--iterations", type=int, default=1000,
                     help="Signatures per session (ignored if --duration is set)")
    ap.add_argument("--duration", type=float, default=0.0,
                     help="Run each session for this many seconds instead of a fixed iteration count")
    ap.add_argument("--threads", type=int, default=1,
                     help="Number of concurrent PKCS#11 sessions/threads (simulates concurrent clients)")
    ap.add_argument("--csv", default=None, help="Optional path to write raw per-signature latencies")
    args = ap.parse_args()

    if not args.lib:
        sys.exit("ERROR: --lib (path to Primus PKCS#11 library) is required (or set PKCS11_LIB).")
    if not args.pin:
        sys.exit("ERROR: --pin is required (or set PKCS11_PIN).")

    # Resolve the slot once up-front using a throwaway load of the library.
    probe = PyKCS11.PyKCS11Lib()
    probe.load(args.lib)
    slot = pick_slot(probe, args.slot)
    info = probe.getTokenInfo(slot)
    print(f"Using slot {slot} — token label: {info.label.strip()}, "
          f"model: {info.model.strip()}, firmware: {info.firmwareVersion}")

    key_type_cfg = KEY_TYPES[args.key_type]
    results = [ThreadResult(thread_id=i) for i in range(args.threads)]
    stop_event = threading.Event()

    threads = [
        threading.Thread(
            target=worker,
            args=(i, args.lib, slot, args.pin, key_type_cfg, args.iterations, args.duration, stop_event, results[i]),
            daemon=True,
        )
        for i in range(args.threads)
    ]

    print(f"Generating key ({args.key_type}) and starting {args.threads} session(s)...")
    t_start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall_time_s = time.perf_counter() - t_start

    throughput, ok, err, _ = print_summary(results, wall_time_s, args.key_type, args.threads)

    if args.csv:
        write_csv(args.csv, results)
        print(f"Raw per-signature latencies written to {args.csv}")

    if err > 0 and ok == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
