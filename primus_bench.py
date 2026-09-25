#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
primus_bench.py - Multi-threaded PKCS#11 performance benchmark for
                  Securosys Primus HSM / CloudHSM (Primus PKCS#11 Provider).

  * Pure Python 3.8+ standard library (ctypes). No pip packages needed.
  * Windows (primusP11.dll) and Linux (libprimusP11.so).
  * Classic + PQC: RSA, ECDSA, EdDSA, ECDH, AES, HMAC, CMAC, KWP,
    ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203).
  * N threads per slot, optional multi-process mode to go past the Python GIL.

PQC requires Primus PKCS#11 Provider >= 2.6.2 (PKCS#11 v3.2) and HSM firmware >= 3.1.

Examples
  python primus_bench.py -list
  python primus_bench.py -mechs -s 0
  python primus_bench.py -m rsasigver -k 2048 -ns 0x8 -t 30
  python primus_bench.py -m ecdsasigver -c p256 -ns 0x16 -t 30 -nov
  python primus_bench.py -m mldsasigver -param 65 -ns 0x8 -t 30
  python primus_bench.py -m slhdsasigver -param sha2-128f -ns 0x4 -t 30
  python primus_bench.py -m mlkemencap -param 768 -ns 0x8 -t 30
  python primus_bench.py -m aesenc -aesmode gcm -p 1024 -ns 0x8 -t 30 -procs 4
"""

import argparse
import csv
import ctypes
import datetime
import getpass
import multiprocessing as mp
import os
import platform
import queue
import random
import sys
import threading
import time
from ctypes import (POINTER, addressof, byref, c_char, c_char_p, c_ubyte,
                    c_ulong, c_void_p, sizeof)

TOOL_NAME = "primus_bench"
TOOL_VERSION = "1.2.0"
IS_WIN = sys.platform.startswith("win")
LABEL_PREFIX = "p11bench_"
SIG_BUF = 65536          # large enough for SLH-DSA-256f (49,856 bytes)
MAX_SAMPLES = 20000      # latency samples kept per label per thread

DEFAULT_LIBS = (
    [r"C:\Program Files\Securosys\Primus P11\primusP11.dll"] if IS_WIN else
    ["/usr/local/primus/lib/libprimusP11.so", "/usr/lib/libprimusP11.so",
     "/usr/local/lib/libprimusP11.so"]
)


# --------------------------------------------------------------------------
# PKCS#11 constants (standard v3.2 values). Override with -const NAME=0xVAL
# if your Primus header (.../Primus P11/include) says otherwise.
# --------------------------------------------------------------------------
class K:
    # return values
    CKR_OK = 0x0
    CKR_ATTRIBUTE_TYPE_INVALID = 0x12
    CKR_ATTRIBUTE_VALUE_INVALID = 0x13
    CKR_MECHANISM_INVALID = 0x70
    CKR_MECHANISM_PARAM_INVALID = 0x71
    CKR_TEMPLATE_INCOMPLETE = 0xD0
    CKR_TEMPLATE_INCONSISTENT = 0xD1
    CKR_USER_ALREADY_LOGGED_IN = 0x100
    CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
    # flags / users
    CKF_RW_SESSION = 0x2
    CKF_SERIAL_SESSION = 0x4
    CKF_OS_LOCKING_OK = 0x2
    CKF_TOKEN_PRESENT = 0x1
    CKU_USER = 1
    # object classes / key types
    CKO_PUBLIC_KEY = 2
    CKO_PRIVATE_KEY = 3
    CKO_SECRET_KEY = 4
    CKK_RSA = 0x0
    CKK_EC = 0x3
    CKK_GENERIC_SECRET = 0x10
    CKK_AES = 0x1F
    CKK_EC_EDWARDS = 0x40
    CKK_ML_KEM = 0x49
    CKK_ML_DSA = 0x4A
    CKK_SLH_DSA = 0x4B
    # attributes
    CKA_CLASS = 0x0
    CKA_TOKEN = 0x1
    CKA_PRIVATE = 0x2
    CKA_LABEL = 0x3
    CKA_KEY_TYPE = 0x100
    CKA_SENSITIVE = 0x103
    CKA_ENCRYPT = 0x104
    CKA_DECRYPT = 0x105
    CKA_WRAP = 0x106
    CKA_UNWRAP = 0x107
    CKA_SIGN = 0x108
    CKA_VERIFY = 0x10A
    CKA_DERIVE = 0x10C
    CKA_MODULUS_BITS = 0x121
    CKA_PUBLIC_EXPONENT = 0x122
    CKA_VALUE_LEN = 0x161
    CKA_EXTRACTABLE = 0x162
    CKA_EC_PARAMS = 0x180
    CKA_EC_POINT = 0x181
    CKA_PARAMETER_SET = 0x61D
    CKA_ENCAPSULATE = 0x633
    CKA_DECAPSULATE = 0x634
    # mechanisms - RSA
    CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0
    CKM_RSA_PKCS = 0x1
    CKM_RSA_PKCS_OAEP = 0x9
    CKM_RSA_PKCS_PSS = 0xD
    CKM_SHA1_RSA_PKCS = 0x6
    CKM_SHA1_RSA_PKCS_PSS = 0xE
    CKM_SHA256_RSA_PKCS = 0x40
    CKM_SHA384_RSA_PKCS = 0x41
    CKM_SHA512_RSA_PKCS = 0x42
    CKM_SHA256_RSA_PKCS_PSS = 0x43
    CKM_SHA384_RSA_PKCS_PSS = 0x44
    CKM_SHA512_RSA_PKCS_PSS = 0x45
    CKM_SHA224_RSA_PKCS = 0x46
    CKM_SHA224_RSA_PKCS_PSS = 0x47
    # digests / HMAC
    CKM_SHA_1 = 0x220
    CKM_SHA_1_HMAC = 0x221
    CKM_SHA256 = 0x250
    CKM_SHA256_HMAC = 0x251
    CKM_SHA224 = 0x255
    CKM_SHA224_HMAC = 0x256
    CKM_SHA384 = 0x260
    CKM_SHA384_HMAC = 0x261
    CKM_SHA512 = 0x270
    CKM_SHA512_HMAC = 0x271
    CKM_SHA3_256 = 0x2B0
    CKM_SHA3_256_HMAC = 0x2B1
    CKM_SHA3_384 = 0x2C0
    CKM_SHA3_384_HMAC = 0x2C1
    CKM_SHA3_512 = 0x2D0
    CKM_SHA3_512_HMAC = 0x2D1
    CKM_GENERIC_SECRET_KEY_GEN = 0x350
    # EC / Edwards
    CKM_EC_KEY_PAIR_GEN = 0x1040
    CKM_ECDSA = 0x1041
    CKM_ECDSA_SHA1 = 0x1042
    CKM_ECDSA_SHA224 = 0x1043
    CKM_ECDSA_SHA256 = 0x1044
    CKM_ECDSA_SHA384 = 0x1045
    CKM_ECDSA_SHA512 = 0x1046
    CKM_ECDH1_DERIVE = 0x1050
    CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055
    CKM_EDDSA = 0x1057
    # AES
    CKM_AES_KEY_GEN = 0x1080
    CKM_AES_ECB = 0x1081
    CKM_AES_CBC = 0x1082
    CKM_AES_CBC_PAD = 0x1085
    CKM_AES_CTR = 0x1086
    CKM_AES_GCM = 0x1087
    CKM_AES_CMAC = 0x108A
    CKM_AES_KEY_WRAP = 0x2109
    CKM_AES_KEY_WRAP_PAD = 0x210A
    # PQC (PKCS#11 v3.2)
    CKM_ML_KEM_KEY_PAIR_GEN = 0x0F
    CKM_ML_KEM = 0x17
    CKM_ML_DSA_KEY_PAIR_GEN = 0x1C
    CKM_ML_DSA = 0x1D
    CKM_SLH_DSA_KEY_PAIR_GEN = 0x2D
    CKM_SLH_DSA = 0x2E
    # misc
    CKG_MGF1_SHA1 = 0x1
    CKG_MGF1_SHA256 = 0x2
    CKG_MGF1_SHA384 = 0x3
    CKG_MGF1_SHA512 = 0x4
    CKG_MGF1_SHA224 = 0x5
    CKD_NULL = 0x1
    CKZ_DATA_SPECIFIED = 0x1


CKR_NAMES = {
    0x0: "CKR_OK", 0x1: "CKR_CANCEL", 0x2: "CKR_HOST_MEMORY", 0x3: "CKR_SLOT_ID_INVALID",
    0x5: "CKR_GENERAL_ERROR", 0x6: "CKR_FUNCTION_FAILED", 0x7: "CKR_ARGUMENTS_BAD",
    0x12: "CKR_ATTRIBUTE_TYPE_INVALID", 0x13: "CKR_ATTRIBUTE_VALUE_INVALID",
    0x20: "CKR_DATA_INVALID", 0x21: "CKR_DATA_LEN_RANGE", 0x30: "CKR_DEVICE_ERROR",
    0x31: "CKR_DEVICE_MEMORY", 0x32: "CKR_DEVICE_REMOVED", 0x40: "CKR_ENCRYPTED_DATA_INVALID",
    0x41: "CKR_ENCRYPTED_DATA_LEN_RANGE", 0x54: "CKR_FUNCTION_NOT_SUPPORTED",
    0x60: "CKR_KEY_HANDLE_INVALID", 0x62: "CKR_KEY_SIZE_RANGE", 0x63: "CKR_KEY_TYPE_INCONSISTENT",
    0x68: "CKR_KEY_FUNCTION_NOT_PERMITTED", 0x6A: "CKR_KEY_UNEXTRACTABLE",
    0x70: "CKR_MECHANISM_INVALID", 0x71: "CKR_MECHANISM_PARAM_INVALID",
    0x82: "CKR_OBJECT_HANDLE_INVALID", 0x90: "CKR_OPERATION_ACTIVE",
    0x91: "CKR_OPERATION_NOT_INITIALIZED", 0xA0: "CKR_PIN_INCORRECT", 0xA4: "CKR_PIN_LOCKED",
    0xB0: "CKR_SESSION_CLOSED", 0xB1: "CKR_SESSION_COUNT", 0xB3: "CKR_SESSION_HANDLE_INVALID",
    0xC0: "CKR_SIGNATURE_INVALID", 0xC1: "CKR_SIGNATURE_LEN_RANGE",
    0xD0: "CKR_TEMPLATE_INCOMPLETE", 0xD1: "CKR_TEMPLATE_INCONSISTENT",
    0xE0: "CKR_TOKEN_NOT_PRESENT", 0x100: "CKR_USER_ALREADY_LOGGED_IN",
    0x101: "CKR_USER_NOT_LOGGED_IN", 0x150: "CKR_BUFFER_TOO_SMALL",
    0x190: "CKR_CRYPTOKI_NOT_INITIALIZED", 0x191: "CKR_CRYPTOKI_ALREADY_INITIALIZED",
}


def ckr_name(rv):
    if rv in CKR_NAMES:
        return CKR_NAMES[rv]
    return "CKR_VENDOR_DEFINED" if rv & 0x80000000 else "UNKNOWN"


def mech_names():
    return {v: n for n, v in vars(K).items() if n.startswith("CKM_")}


PQC_MECHS = ("CKM_ML_DSA_KEY_PAIR_GEN", "CKM_ML_DSA", "CKM_SLH_DSA_KEY_PAIR_GEN",
             "CKM_SLH_DSA", "CKM_ML_KEM_KEY_PAIR_GEN", "CKM_ML_KEM")


# --------------------------------------------------------------------------
# ctypes structures. Windows cryptoki uses 1-byte packing.
# --------------------------------------------------------------------------
def _struct(name, fields):
    ns = {"_fields_": fields}
    if IS_WIN:
        ns["_pack_"] = 1
    return type(name, (ctypes.Structure,), ns)


CK_ULONG = c_ulong
CK_VERSION = _struct("CK_VERSION", [("major", c_ubyte), ("minor", c_ubyte)])
CK_INFO = _struct("CK_INFO", [
    ("cryptokiVersion", CK_VERSION), ("manufacturerID", c_char * 32), ("flags", CK_ULONG),
    ("libraryDescription", c_char * 32), ("libraryVersion", CK_VERSION)])
CK_SLOT_INFO = _struct("CK_SLOT_INFO", [
    ("slotDescription", c_char * 64), ("manufacturerID", c_char * 32), ("flags", CK_ULONG),
    ("hardwareVersion", CK_VERSION), ("firmwareVersion", CK_VERSION)])
CK_TOKEN_INFO = _struct("CK_TOKEN_INFO", [
    ("label", c_char * 32), ("manufacturerID", c_char * 32), ("model", c_char * 16),
    ("serialNumber", c_char * 16), ("flags", CK_ULONG),
    ("ulMaxSessionCount", CK_ULONG), ("ulSessionCount", CK_ULONG),
    ("ulMaxRwSessionCount", CK_ULONG), ("ulRwSessionCount", CK_ULONG),
    ("ulMaxPinLen", CK_ULONG), ("ulMinPinLen", CK_ULONG),
    ("ulTotalPublicMemory", CK_ULONG), ("ulFreePublicMemory", CK_ULONG),
    ("ulTotalPrivateMemory", CK_ULONG), ("ulFreePrivateMemory", CK_ULONG),
    ("hardwareVersion", CK_VERSION), ("firmwareVersion", CK_VERSION), ("utcTime", c_char * 16)])
CK_MECHANISM_INFO = _struct("CK_MECHANISM_INFO", [
    ("ulMinKeySize", CK_ULONG), ("ulMaxKeySize", CK_ULONG), ("flags", CK_ULONG)])
CK_ATTRIBUTE = _struct("CK_ATTRIBUTE", [
    ("type", CK_ULONG), ("pValue", c_void_p), ("ulValueLen", CK_ULONG)])
CK_MECHANISM = _struct("CK_MECHANISM", [
    ("mechanism", CK_ULONG), ("pParameter", c_void_p), ("ulParameterLen", CK_ULONG)])
CK_C_INITIALIZE_ARGS = _struct("CK_C_INITIALIZE_ARGS", [
    ("CreateMutex", c_void_p), ("DestroyMutex", c_void_p), ("LockMutex", c_void_p),
    ("UnlockMutex", c_void_p), ("flags", CK_ULONG), ("pReserved", c_void_p)])
CK_GCM_PARAMS = _struct("CK_GCM_PARAMS", [
    ("pIv", c_void_p), ("ulIvLen", CK_ULONG), ("ulIvBits", CK_ULONG),
    ("pAAD", c_void_p), ("ulAADLen", CK_ULONG), ("ulTagBits", CK_ULONG)])
CK_AES_CTR_PARAMS = _struct("CK_AES_CTR_PARAMS", [
    ("ulCounterBits", CK_ULONG), ("cb", c_ubyte * 16)])
CK_RSA_PKCS_PSS_PARAMS = _struct("CK_RSA_PKCS_PSS_PARAMS", [
    ("hashAlg", CK_ULONG), ("mgf", CK_ULONG), ("sLen", CK_ULONG)])
CK_RSA_PKCS_OAEP_PARAMS = _struct("CK_RSA_PKCS_OAEP_PARAMS", [
    ("hashAlg", CK_ULONG), ("mgf", CK_ULONG), ("source", CK_ULONG),
    ("pSourceData", c_void_p), ("ulSourceDataLen", CK_ULONG)])
CK_ECDH1_DERIVE_PARAMS = _struct("CK_ECDH1_DERIVE_PARAMS", [
    ("kdf", CK_ULONG), ("ulSharedDataLen", CK_ULONG), ("pSharedData", c_void_p),
    ("ulPublicDataLen", CK_ULONG), ("pPublicData", c_void_p)])
CK_EDDSA_PARAMS = _struct("CK_EDDSA_PARAMS", [
    ("phFlag", c_ubyte), ("ulContextDataLen", CK_ULONG), ("pContextData", c_void_p)])
CK_INTERFACE = _struct("CK_INTERFACE", [
    ("pInterfaceName", c_char_p), ("pFunctionList", c_void_p), ("flags", CK_ULONG)])


class P11Error(Exception):
    def __init__(self, fn, rv):
        self.fn, self.rv = fn, rv
        super().__init__("%s failed: 0x%08X (%s)" % (fn, rv, ckr_name(rv)))


def ck(fn, rv):
    if rv != 0:
        raise P11Error(fn, rv)


def cstr(b):
    return b.decode("utf-8", "replace").rstrip(" \x00")


# --------------------------------------------------------------------------
# Library wrapper
# --------------------------------------------------------------------------
_U, _PU, _P = CK_ULONG, POINTER(CK_ULONG), c_void_p
PROTOS = {
    "C_Initialize": [_P], "C_Finalize": [_P], "C_GetInfo": [_P],
    "C_GetSlotList": [c_ubyte, _P, _PU], "C_GetSlotInfo": [_U, _P], "C_GetTokenInfo": [_U, _P],
    "C_GetMechanismList": [_U, _P, _PU], "C_GetMechanismInfo": [_U, _U, _P],
    "C_OpenSession": [_U, _U, _P, _P, _PU], "C_CloseSession": [_U],
    "C_Login": [_U, _U, _P, _U],
    "C_DestroyObject": [_U, _U], "C_GetAttributeValue": [_U, _U, _P, _U],
    "C_FindObjectsInit": [_U, _P, _U], "C_FindObjects": [_U, _PU, _U, _PU],
    "C_FindObjectsFinal": [_U],
    "C_EncryptInit": [_U, _P, _U], "C_Encrypt": [_U, _P, _U, _P, _PU],
    "C_DecryptInit": [_U, _P, _U], "C_Decrypt": [_U, _P, _U, _P, _PU],
    "C_DigestInit": [_U, _P], "C_Digest": [_U, _P, _U, _P, _PU],
    "C_SignInit": [_U, _P, _U], "C_Sign": [_U, _P, _U, _P, _PU],
    "C_VerifyInit": [_U, _P, _U], "C_Verify": [_U, _P, _U, _P, _U],
    "C_GenerateKey": [_U, _P, _P, _U, _PU],
    "C_GenerateKeyPair": [_U, _P, _P, _U, _P, _U, _PU, _PU],
    "C_WrapKey": [_U, _P, _U, _U, _P, _PU],
    "C_UnwrapKey": [_U, _P, _U, _P, _U, _P, _U, _PU],
    "C_DeriveKey": [_U, _P, _U, _P, _U, _PU],
    "C_GenerateRandom": [_U, _P, _U],
}
ENCAP_ARGS = [_U, _P, _U, _P, _U, _P, _PU, _PU]   # sess, mech, hPub, tmpl, n, ct, *ctLen, *hKey
DECAP_ARGS = [_U, _P, _U, _P, _U, _P, _U, _PU]    # sess, mech, hPriv, tmpl, n, ct, ctLen, *hKey
FL_IDX_ENCAP = 92   # index in CK_FUNCTION_LIST_3_2 (68 v2.40 + 24 v3.0 entries)
FL_IDX_DECAP = 93


def resolve_lib(path):
    cands = [path] if path else ([os.environ["PRIMUS_P11_LIB"]] if os.environ.get("PRIMUS_P11_LIB") else [])
    cands += DEFAULT_LIBS if not path else []
    if os.environ.get("PRIMUS_HOME") and not path:
        name = "primusP11.dll" if IS_WIN else os.path.join("lib", "libprimusP11.so")
        cands.insert(0, os.path.join(os.environ["PRIMUS_HOME"], name))
    for c in cands:
        if c and os.path.isfile(c):
            return c
    raise SystemExit("Primus PKCS#11 library not found. Use -lib <path> or set PRIMUS_P11_LIB.\n"
                     "Tried: " + ", ".join(c for c in cands if c))


class Lib:
    def __init__(self, path):
        self.path = resolve_lib(path)
        d = os.path.dirname(os.path.abspath(self.path))
        if IS_WIN and hasattr(os, "add_dll_directory"):
            os.add_dll_directory(d)
        self.dll = ctypes.CDLL(self.path)
        for name, args in PROTOS.items():
            f = getattr(self.dll, name)
            f.argtypes, f.restype = args, CK_ULONG
            setattr(self, name, f)
        a = CK_C_INITIALIZE_ARGS()
        a.flags = K.CKF_OS_LOCKING_OK
        rv = self.C_Initialize(byref(a))
        if rv not in (0, K.CKR_CRYPTOKI_ALREADY_INITIALIZED):
            raise P11Error("C_Initialize", rv)
        self.kem_source = self._init_kem()

    def _init_kem(self):
        """Locate C_EncapsulateKey / C_DecapsulateKey (PKCS#11 v3.2)."""
        self.C_EncapsulateKey = self.C_DecapsulateKey = None
        try:
            e, d = self.dll.C_EncapsulateKey, self.dll.C_DecapsulateKey
            e.argtypes, e.restype = ENCAP_ARGS, CK_ULONG
            d.argtypes, d.restype = DECAP_ARGS, CK_ULONG
            self.C_EncapsulateKey, self.C_DecapsulateKey = e, d
            return "exported symbols"
        except AttributeError:
            pass
        try:
            gi = self.dll.C_GetInterface
            gi.argtypes, gi.restype = [c_char_p, _P, _P, _U], CK_ULONG
            ver = CK_VERSION(3, 2)
            pif = POINTER(CK_INTERFACE)()
            if gi(b"PKCS 11", byref(ver), byref(pif), 0) != 0 or not pif:
                return None
            fl = pif.contents.pFunctionList
            v = (c_ubyte * 2).from_address(fl)
            if (v[0], v[1]) < (3, 2):
                return None
            base = 2 if IS_WIN else sizeof(c_void_p)
            ptr = lambda i: c_void_p.from_address(fl + base + i * sizeof(c_void_p)).value
            self.C_EncapsulateKey = ctypes.CFUNCTYPE(CK_ULONG, *ENCAP_ARGS)(ptr(FL_IDX_ENCAP))
            self.C_DecapsulateKey = ctypes.CFUNCTYPE(CK_ULONG, *DECAP_ARGS)(ptr(FL_IDX_DECAP))
            return "C_GetInterface v3.2 function list"
        except AttributeError:
            return None

    def finalize(self):
        try:
            self.C_Finalize(None)
        except Exception:
            pass

    def info(self):
        i = CK_INFO()
        ck("C_GetInfo", self.C_GetInfo(byref(i)))
        return i

    def slots(self, present=True):
        n = CK_ULONG()
        ck("C_GetSlotList", self.C_GetSlotList(1 if present else 0, None, byref(n)))
        arr = (CK_ULONG * max(n.value, 1))()
        ck("C_GetSlotList", self.C_GetSlotList(1 if present else 0, arr, byref(n)))
        return list(arr[:n.value])

    def token_info(self, slot):
        t = CK_TOKEN_INFO()
        ck("C_GetTokenInfo", self.C_GetTokenInfo(slot, byref(t)))
        return t

    def mechanisms(self, slot):
        n = CK_ULONG()
        ck("C_GetMechanismList", self.C_GetMechanismList(slot, None, byref(n)))
        arr = (CK_ULONG * max(n.value, 1))()
        ck("C_GetMechanismList", self.C_GetMechanismList(slot, arr, byref(n)))
        out = []
        for m in arr[:n.value]:
            mi = CK_MECHANISM_INFO()
            self.C_GetMechanismInfo(slot, m, byref(mi))
            out.append((m, mi.ulMinKeySize, mi.ulMaxKeySize, mi.flags))
        return out


# --------------------------------------------------------------------------
# Helpers: templates, mechanisms, sessions
# --------------------------------------------------------------------------
class Tmpl:
    """CK_ATTRIBUTE array built from [(type, value)]. Keeps buffers alive."""
    def __init__(self, items):
        self.items = list(items)
        self.n = len(self.items)
        self.arr = (CK_ATTRIBUTE * max(self.n, 1))()
        self._keep = []
        for i, (t, v) in enumerate(self.items):
            if isinstance(v, bool):
                b, ln = (c_ubyte * 1)(1 if v else 0), 1
            elif isinstance(v, int):
                b, ln = CK_ULONG(v), sizeof(CK_ULONG)
            else:
                if isinstance(v, str):
                    v = v.encode()
                b, ln = ctypes.create_string_buffer(v, len(v)), len(v)
            self._keep.append(b)
            self.arr[i].type, self.arr[i].pValue, self.arr[i].ulValueLen = t, addressof(b), ln

    def without(self, drop):
        return Tmpl([x for x in self.items if x[0] not in drop])


class Mech:
    """CK_MECHANISM. Parameter buffers are pinned on the struct so they live as
    long as any byref() to it (closures only hold .ref)."""
    def __init__(self, mtype, param=None):
        self.s = CK_MECHANISM()
        self.s.mechanism = mtype
        self.s._keep = [param]
        if param is not None:
            self.s.pParameter, self.s.ulParameterLen = addressof(param), sizeof(param)
        self.ref = byref(self.s)

    def pin(self, obj):
        self.s._keep.append(obj)
        return obj


def get_attr(lib, h, obj, atype):
    a = CK_ATTRIBUTE(atype, None, 0)
    ck("C_GetAttributeValue", lib.C_GetAttributeValue(h, obj, byref(a), 1))
    buf = ctypes.create_string_buffer(a.ulValueLen)
    a.pValue = addressof(buf)
    ck("C_GetAttributeValue", lib.C_GetAttributeValue(h, obj, byref(a), 1))
    return buf.raw[:a.ulValueLen]


def open_session(lib, slot, pin):
    h = CK_ULONG()
    ck("C_OpenSession", lib.C_OpenSession(slot, K.CKF_SERIAL_SESSION | K.CKF_RW_SESSION,
                                          None, None, byref(h)))
    if pin is not None:
        p = pin.encode()
        rv = lib.C_Login(h.value, K.CKU_USER, p, len(p))
        if rv not in (0, K.CKR_USER_ALREADY_LOGGED_IN):
            lib.C_CloseSession(h.value)
            raise P11Error("C_Login", rv)
    return h.value


RETRYABLE = None  # filled lazily (K may be overridden)


def _retryable():
    return (K.CKR_ATTRIBUTE_TYPE_INVALID, K.CKR_ATTRIBUTE_VALUE_INVALID,
            K.CKR_TEMPLATE_INCOMPLETE, K.CKR_TEMPLATE_INCONSISTENT)


class KeyPairGen:
    """Resolves a working (pub, priv) template pair once, then generates fast."""
    def __init__(self, lib, h, mtype, candidates, param=None):
        self.lib, self.h, self.mech = lib, h, Mech(mtype, param)
        last = None
        for pub, priv in candidates:
            self.tp, self.tk = Tmpl(pub), Tmpl(priv)
            try:
                t = time.perf_counter()
                self.first = self.gen()
                self.first_ms = (time.perf_counter() - t) * 1000.0
                return
            except P11Error as e:
                last = e
                if e.rv not in _retryable():
                    raise
        raise last

    def gen(self):
        hp, hk = CK_ULONG(), CK_ULONG()
        ck("C_GenerateKeyPair", self.lib.C_GenerateKeyPair(
            self.h, self.mech.ref, self.tp.arr, self.tp.n, self.tk.arr, self.tk.n,
            byref(hp), byref(hk)))
        return hp.value, hk.value


class SecretGen:
    def __init__(self, lib, h, mtype, items):
        self.lib, self.h, self.mech, self.t = lib, h, Mech(mtype), Tmpl(items)

    def gen(self):
        hk = CK_ULONG()
        ck("C_GenerateKey", self.lib.C_GenerateKey(self.h, self.mech.ref, self.t.arr, self.t.n,
                                                   byref(hk)))
        return hk.value


# --------------------------------------------------------------------------
# Algorithm tables
# --------------------------------------------------------------------------
CURVES = {
    "p224": bytes.fromhex("06052b81040021"),
    "p256": bytes.fromhex("06082a8648ce3d030107"),
    "p384": bytes.fromhex("06052b81040022"),
    "p521": bytes.fromhex("06052b81040023"),
    "secp256k1": bytes.fromhex("06052b8104000a"),
    "brainpool256r1": bytes.fromhex("06092b2403030208010107"),
    "brainpool384r1": bytes.fromhex("06092b240303020801010b"),
    "brainpool512r1": bytes.fromhex("06092b240303020801010d"),
}
CURVE_BYTES = {"p224": 28, "p256": 32, "p384": 48, "p521": 66, "secp256k1": 32,
               "brainpool256r1": 32, "brainpool384r1": 48, "brainpool512r1": 64}
ED_CURVES = {"ed25519": bytes.fromhex("06032b6570"), "ed448": bytes.fromhex("06032b6571")}

HASH_LEN = {"sha1": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64,
            "sha3-256": 32, "sha3-384": 48, "sha3-512": 64}


def hash_mech(hn):
    return {"sha1": K.CKM_SHA_1, "sha224": K.CKM_SHA224, "sha256": K.CKM_SHA256,
            "sha384": K.CKM_SHA384, "sha512": K.CKM_SHA512, "sha3-256": K.CKM_SHA3_256,
            "sha3-384": K.CKM_SHA3_384, "sha3-512": K.CKM_SHA3_512}[hn]


def hmac_mech(hn):
    return {"sha1": K.CKM_SHA_1_HMAC, "sha224": K.CKM_SHA224_HMAC, "sha256": K.CKM_SHA256_HMAC,
            "sha384": K.CKM_SHA384_HMAC, "sha512": K.CKM_SHA512_HMAC,
            "sha3-256": K.CKM_SHA3_256_HMAC, "sha3-384": K.CKM_SHA3_384_HMAC,
            "sha3-512": K.CKM_SHA3_512_HMAC}[hn]


def mgf(hn):
    return {"sha1": K.CKG_MGF1_SHA1, "sha224": K.CKG_MGF1_SHA224, "sha256": K.CKG_MGF1_SHA256,
            "sha384": K.CKG_MGF1_SHA384, "sha512": K.CKG_MGF1_SHA512}[hn]


def rsa_pkcs_mech(hn):
    return {"none": K.CKM_RSA_PKCS, "sha1": K.CKM_SHA1_RSA_PKCS, "sha224": K.CKM_SHA224_RSA_PKCS,
            "sha256": K.CKM_SHA256_RSA_PKCS, "sha384": K.CKM_SHA384_RSA_PKCS,
            "sha512": K.CKM_SHA512_RSA_PKCS}[hn]


def rsa_pss_mech(hn):
    return {"sha1": K.CKM_SHA1_RSA_PKCS_PSS, "sha224": K.CKM_SHA224_RSA_PKCS_PSS,
            "sha256": K.CKM_SHA256_RSA_PKCS_PSS, "sha384": K.CKM_SHA384_RSA_PKCS_PSS,
            "sha512": K.CKM_SHA512_RSA_PKCS_PSS}[hn]


def ecdsa_mech(hn):
    return {"none": K.CKM_ECDSA, "sha1": K.CKM_ECDSA_SHA1, "sha224": K.CKM_ECDSA_SHA224,
            "sha256": K.CKM_ECDSA_SHA256, "sha384": K.CKM_ECDSA_SHA384,
            "sha512": K.CKM_ECDSA_SHA512}[hn]


ML_DSA_SETS = {"44": 1, "65": 2, "87": 3}
ML_KEM_SETS = {"512": 1, "768": 2, "1024": 3}
ML_KEM_CT = {"512": 768, "768": 1088, "1024": 1568}
SLH_DSA_SETS = {"sha2-128s": 1, "shake-128s": 2, "sha2-128f": 3, "shake-128f": 4,
                "sha2-192s": 5, "shake-192s": 6, "sha2-192f": 7, "shake-192f": 8,
                "sha2-256s": 9, "shake-256s": 10, "sha2-256f": 11, "shake-256f": 12}


# --------------------------------------------------------------------------
# Per-thread worker context and step builders
# --------------------------------------------------------------------------
def label_of(tmpl):
    for t, v in tmpl.items:
        if t == K.CKA_LABEL:
            return v if isinstance(v, str) else v.decode("utf-8", "replace")
    return ""


class KeyShare:
    """Process-wide cache of test keys, one set per slot, shared by all threads.
    Handles of token objects are valid in every session of the same process."""
    def __init__(self):
        self.lock = threading.Lock()
        self.slot_locks = {}
        self.cache = {}

    def get(self, slot, name, create):
        with self.lock:
            lk = self.slot_locks.setdefault(slot, threading.Lock())
        with lk:
            key = (slot, name)
            if key not in self.cache:
                self.cache[key] = create()
            return self.cache[key]


class W:
    """Per-thread context: library, session, config, keys created on the HSM."""
    def __init__(self, lib, h, slot, cfg, tag, share=None):
        self.lib, self.h, self.slot, self.cfg, self.tag = lib, h, slot, cfg, tag
        self.share = share  # KeyShare when all threads of a slot use one key set
        self.keys = []      # dicts: h, cls, desc, label, ms, pair (keys this thread owns)
        self.note = ""
        self.sig_len = None

    def shared(self, name, create):
        """Return the key(s) named `name` for this slot. In shared-key mode only the
        first thread creates them; every other thread on the slot reuses the handles."""
        if self.share is None:
            return create()
        return self.share.get(self.slot, name, create)

    def label(self, suffix=""):
        return "%s%s%s" % (LABEL_PREFIX, self.tag, suffix)

    @property
    def tok(self):
        return not self.cfg["session"]

    def add_pair(self, g, desc, handles=None, ms=None):
        """Register a generated key pair (shown in the key table, deleted at the end)."""
        pub, prv = handles if handles else g.first
        ms = g.first_ms if ms is None else ms
        for hdl, cls, t in ((pub, "public", g.tp), (prv, "private", g.tk)):
            self.keys.append({"h": hdl, "cls": cls, "desc": desc, "label": label_of(t),
                              "ms": ms, "pair": True})
        return pub, prv

    def gen_pair(self, g, desc):
        """Generate one more pair with an existing KeyPairGen and register it."""
        t = time.perf_counter()
        handles = g.gen()
        return self.add_pair(g, desc, handles, (time.perf_counter() - t) * 1000.0)

    def add_secret(self, sg, desc):
        t = time.perf_counter()
        hk = sg.gen()
        ms = (time.perf_counter() - t) * 1000.0
        self.keys.append({"h": hk, "cls": "secret", "desc": desc, "label": label_of(sg.t),
                          "ms": ms, "pair": False})
        return hk


def payload(cfg, default=64, align=1):
    n = cfg["packet"] or default
    if align > 1 and n % align:
        n += align - (n % align)
    return os.urandom(n)


def sign_verify_steps(w, mech, priv, pub, data):
    L, h, m, cfg = w.lib, w.h, mech.ref, w.cfg
    dbuf, dlen = ctypes.create_string_buffer(data, len(data)), len(data)
    sig, slen = ctypes.create_string_buffer(SIG_BUF), CK_ULONG(SIG_BUF)
    sref = byref(slen)
    SignInit, Sign, VerifyInit, Verify = L.C_SignInit, L.C_Sign, L.C_VerifyInit, L.C_Verify

    def do_sign():
        rv = SignInit(h, m, priv)
        if rv:
            raise P11Error("C_SignInit", rv)
        slen.value = SIG_BUF
        rv = Sign(h, dbuf, dlen, sig, sref)
        if rv:
            raise P11Error("C_Sign", rv)

    do_sign()
    ref = sig.raw[:slen.value]
    vsig, vlen = ctypes.create_string_buffer(ref, len(ref)), len(ref)

    def do_verify():
        rv = VerifyInit(h, m, pub)
        if rv:
            raise P11Error("C_VerifyInit", rv)
        rv = Verify(h, dbuf, dlen, vsig, vlen)
        if rv:
            raise P11Error("C_Verify", rv)

    do_verify()
    w.sig_len = len(ref)
    steps = []
    if not cfg["nosign"]:
        steps.append(("sign", do_sign))
    if not cfg["noverify"]:
        steps.append(("verify", do_verify))
    return steps


def enc_dec_steps(w, mech, enc_key, dec_key, data, refresh_iv=None):
    L, h, m, cfg = w.lib, w.h, mech.ref, w.cfg
    pbuf, plen = ctypes.create_string_buffer(data, len(data)), len(data)
    cap = len(data) + 1024
    ct, clen = ctypes.create_string_buffer(cap), CK_ULONG(cap)
    pt, ptl = ctypes.create_string_buffer(cap), CK_ULONG(cap)
    cref, pref = byref(clen), byref(ptl)
    EI, E, DI, D = L.C_EncryptInit, L.C_Encrypt, L.C_DecryptInit, L.C_Decrypt
    check = not cfg["noverifyr"]

    def do_enc():
        if refresh_iv:
            refresh_iv()
        rv = EI(h, m, enc_key)
        if rv:
            raise P11Error("C_EncryptInit", rv)
        clen.value = cap
        rv = E(h, pbuf, plen, ct, cref)
        if rv:
            raise P11Error("C_Encrypt", rv)

    def do_dec():
        rv = DI(h, m, dec_key)
        if rv:
            raise P11Error("C_DecryptInit", rv)
        ptl.value = cap
        rv = D(h, ct, clen.value, pt, pref)
        if rv:
            raise P11Error("C_Decrypt", rv)
        if check and ctypes.string_at(pt, ptl.value) != data:
            raise RuntimeError("decrypted data does not match plaintext")

    do_enc()
    do_dec()
    steps = []
    if not cfg["noenc"]:
        steps.append(("encrypt", do_enc))
    if not cfg["nodec"]:
        steps.append(("decrypt", do_dec))
    return steps


# ---- key templates --------------------------------------------------------
def rsa_candidates(w, bits, sign=True, enc=False):
    pub = [(K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label("_rsa_pub")), (K.CKA_MODULUS_BITS, bits),
           (K.CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"), (K.CKA_VERIFY, sign), (K.CKA_ENCRYPT, enc)]
    priv = [(K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label("_rsa_prv")), (K.CKA_PRIVATE, True),
            (K.CKA_SENSITIVE, True), (K.CKA_EXTRACTABLE, False), (K.CKA_SIGN, sign),
            (K.CKA_DECRYPT, enc)]
    return [(pub, priv)]


def ec_candidates(w, params, derive=False, name="_ec"):
    pub = [(K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label(name + "_pub")), (K.CKA_EC_PARAMS, params),
           (K.CKA_VERIFY, not derive)]
    priv = [(K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label(name + "_prv")), (K.CKA_PRIVATE, True),
            (K.CKA_SENSITIVE, True), (K.CKA_EXTRACTABLE, False), (K.CKA_SIGN, not derive),
            (K.CKA_DERIVE, derive)]
    return [(pub, priv)]


def pqc_candidates(w, key_type, pset, pub_use, priv_use, name):
    """Try the spec-clean template first, then fallbacks for provider variations."""
    base_pub = [(K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label(name + "_pub"))] + \
        [(a, True) for a in pub_use]
    base_prv = [(K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label(name + "_prv")), (K.CKA_PRIVATE, True),
                (K.CKA_SENSITIVE, True), (K.CKA_EXTRACTABLE, False)] + [(a, True) for a in priv_use]
    ps = (K.CKA_PARAMETER_SET, pset)
    kt = (K.CKA_KEY_TYPE, key_type)
    return [
        (base_pub + [ps], base_prv),
        (base_pub + [ps, kt], base_prv + [kt]),
        (base_pub + [ps], base_prv + [ps]),
        (base_pub[:2] + [ps], base_prv[:5]),   # no usage flags (HSM defaults)
    ]


def aes_items(w, bits, name="_aes", **use):
    it = [(K.CKA_CLASS, K.CKO_SECRET_KEY), (K.CKA_KEY_TYPE, K.CKK_AES),
          (K.CKA_VALUE_LEN, bits // 8), (K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label(name)),
          (K.CKA_PRIVATE, True), (K.CKA_SENSITIVE, True),
          (K.CKA_EXTRACTABLE, bool(use.pop("extractable", False)))]
    names = {"encrypt": K.CKA_ENCRYPT, "decrypt": K.CKA_DECRYPT, "sign": K.CKA_SIGN,
             "verify": K.CKA_VERIFY, "wrap": K.CKA_WRAP, "unwrap": K.CKA_UNWRAP}
    return it + [(names[k], bool(v)) for k, v in use.items()]


def keygen_step(w, gen_fn, desc, pair=True):
    """Keygen benchmark: every loop creates a key (timed) and destroys it (untimed)."""
    L, h = w.lib, w.h
    w.note = ("%s keys are created and destroyed inside the timed loop "
              "(probe key already deleted)." % desc)

    def do():
        r = gen_fn()
        if pair:
            return lambda: (L.C_DestroyObject(h, r[0]), L.C_DestroyObject(h, r[1]))
        return lambda: L.C_DestroyObject(h, r)
    return [("keygen", do)]


def _drop_probe(w, g):
    w.lib.C_DestroyObject(w.h, g.first[0])
    w.lib.C_DestroyObject(w.h, g.first[1])


# ---- mode builders --------------------------------------------------------
def b_rsakeygen(w):
    bits = w.cfg["key"] or 2048
    g = KeyPairGen(w.lib, w.h, K.CKM_RSA_PKCS_KEY_PAIR_GEN, rsa_candidates(w, bits))
    _drop_probe(w, g)
    return keygen_step(w, g.gen, "RSA-%d" % bits)


def b_rsasigver(w, pss=False):
    c = w.cfg
    bits = c["key"] or 2048
    pub, prv = w.shared("rsa", lambda: w.add_pair(
        KeyPairGen(w.lib, w.h, K.CKM_RSA_PKCS_KEY_PAIR_GEN, rsa_candidates(w, bits)), "RSA-%d" % bits))
    hn = c["hash"]
    if pss:
        if hn == "none":
            raise SystemExit("rsapsssigver needs -hash (sha1/sha224/sha256/sha384/sha512)")
        p = CK_RSA_PKCS_PSS_PARAMS(hash_mech(hn), mgf(hn), HASH_LEN[hn])
        mech, data = Mech(rsa_pss_mech(hn), p), payload(c)
    else:
        mech = Mech(rsa_pkcs_mech(hn))
        data = payload(c, 32) if hn == "none" else payload(c)
    return sign_verify_steps(w, mech, prv, pub, data)


def b_rsapsssigver(w):
    return b_rsasigver(w, pss=True)


def _oaep_hash(c):
    return "sha256" if c["hash"] == "none" else c["hash"]


def b_rsaoaepenc(w):
    c = w.cfg
    hn = _oaep_hash(c)
    bits = c["key"] or 2048
    pub, prv = w.shared("rsa_enc", lambda: w.add_pair(
        KeyPairGen(w.lib, w.h, K.CKM_RSA_PKCS_KEY_PAIR_GEN,
                   rsa_candidates(w, bits, sign=False, enc=True)), "RSA-%d" % bits))
    p = CK_RSA_PKCS_OAEP_PARAMS(hash_mech(hn), mgf(hn), K.CKZ_DATA_SPECIFIED, None, 0)
    return enc_dec_steps(w, Mech(K.CKM_RSA_PKCS_OAEP, p), pub, prv, payload(c, 32))


def _curve(cfg, table, default):
    name = (cfg["curve"] or default).lower()
    if name not in table:
        raise SystemExit("Unknown curve '%s'. Choose: %s" % (name, ", ".join(table)))
    return name, table[name]


def b_eckeygen(w):
    name, params = _curve(w.cfg, CURVES, "p256")
    g = KeyPairGen(w.lib, w.h, K.CKM_EC_KEY_PAIR_GEN, ec_candidates(w, params))
    _drop_probe(w, g)
    return keygen_step(w, g.gen, "EC %s" % name)


def b_ecdsasigver(w):
    c = w.cfg
    name, params = _curve(c, CURVES, "p256")
    pub, prv = w.shared("ec", lambda: w.add_pair(
        KeyPairGen(w.lib, w.h, K.CKM_EC_KEY_PAIR_GEN, ec_candidates(w, params)), "EC %s" % name))
    data = payload(c, 32) if c["hash"] == "none" else payload(c)
    return sign_verify_steps(w, Mech(ecdsa_mech(c["hash"])), prv, pub, data)


def b_ecdhderive(w):
    name, params = _curve(w.cfg, CURVES, "p256")
    L, h = w.lib, w.h
    pubA, prvA = w.shared("ecdhA", lambda: w.add_pair(
        KeyPairGen(L, h, K.CKM_EC_KEY_PAIR_GEN, ec_candidates(w, params, True, "_ecdhA")),
        "EC %s (ECDH A)" % name))
    pubB, prvB = w.shared("ecdhB", lambda: w.add_pair(
        KeyPairGen(L, h, K.CKM_EC_KEY_PAIR_GEN, ec_candidates(w, params, True, "_ecdhB")),
        "EC %s (ECDH B)" % name))
    der_point = get_attr(L, h, pubB, K.CKA_EC_POINT)
    raw_point = der_point[2:] if der_point[0] == 0x04 and der_point[1] < 0x80 else \
        der_point[3:] if der_point[0] == 0x04 else der_point
    tmpl = Tmpl([(K.CKA_CLASS, K.CKO_SECRET_KEY), (K.CKA_KEY_TYPE, K.CKK_GENERIC_SECRET),
                 (K.CKA_VALUE_LEN, CURVE_BYTES[name]), (K.CKA_TOKEN, False),
                 (K.CKA_SENSITIVE, True), (K.CKA_EXTRACTABLE, False)])
    last = None
    for pt in (der_point, raw_point):
        pbuf = ctypes.create_string_buffer(pt, len(pt))
        prm = CK_ECDH1_DERIVE_PARAMS(K.CKD_NULL, 0, None, len(pt), addressof(pbuf))
        mech = Mech(K.CKM_ECDH1_DERIVE, prm)
        mech.pin(pbuf)
        hk = CK_ULONG()
        rv = L.C_DeriveKey(h, mech.ref, prvA, tmpl.arr, tmpl.n, byref(hk))
        if rv == 0:
            L.C_DestroyObject(h, hk.value)
            break
        last = rv
    else:
        raise P11Error("C_DeriveKey", last)
    D = L.C_DeriveKey
    out = CK_ULONG()
    oref = byref(out)

    def do():
        rv = D(h, mech.ref, prvA, tmpl.arr, tmpl.n, oref)
        if rv:
            raise P11Error("C_DeriveKey", rv)
        k = out.value
        return lambda: L.C_DestroyObject(h, k)
    w.note = "Derived shared secrets are session keys, destroyed after each derive (untimed)."
    return [("derive", do)]


def _ed_mech(name):
    if name == "ed448":
        return Mech(K.CKM_EDDSA, CK_EDDSA_PARAMS(0, 0, None))
    return Mech(K.CKM_EDDSA)


def b_eddsakeygen(w):
    name, params = _curve(w.cfg, ED_CURVES, "ed25519")
    g = KeyPairGen(w.lib, w.h, K.CKM_EC_EDWARDS_KEY_PAIR_GEN, ec_candidates(w, params, name="_ed"))
    _drop_probe(w, g)
    return keygen_step(w, g.gen, name)


def b_eddsasigver(w):
    name, params = _curve(w.cfg, ED_CURVES, "ed25519")
    pub, prv = w.shared("ed", lambda: w.add_pair(
        KeyPairGen(w.lib, w.h, K.CKM_EC_EDWARDS_KEY_PAIR_GEN, ec_candidates(w, params, name="_ed")),
        name))
    return sign_verify_steps(w, _ed_mech(name), prv, pub, payload(w.cfg))


def _aes_bits(cfg):
    b = cfg["key"] or 256
    if b not in (128, 192, 256):
        raise SystemExit("AES key size must be 128, 192 or 256")
    return b


def b_aeskeygen(w):
    bits = _aes_bits(w.cfg)
    g = SecretGen(w.lib, w.h, K.CKM_AES_KEY_GEN, aes_items(w, bits, encrypt=True, decrypt=True))
    w.lib.C_DestroyObject(w.h, g.gen())
    return keygen_step(w, g.gen, "AES-%d" % bits, pair=False)


def b_aesenc(w):
    c = w.cfg
    bits = _aes_bits(c)
    key = w.shared("aes", lambda: w.add_secret(SecretGen(
        w.lib, w.h, K.CKM_AES_KEY_GEN, aes_items(w, bits, encrypt=True, decrypt=True)), "AES-%d" % bits))
    mode = c["aesmode"]
    refresh = None
    if mode == "ecb":
        mech, data = Mech(K.CKM_AES_ECB), payload(c, 1024, 16)
    elif mode == "cbc":
        iv = (c_ubyte * 16)(*os.urandom(16))
        mech, data = Mech(K.CKM_AES_CBC, iv), payload(c, 1024, 16)
    elif mode == "cbcpad":
        iv = (c_ubyte * 16)(*os.urandom(16))
        mech, data = Mech(K.CKM_AES_CBC_PAD, iv), payload(c, 1024)
    elif mode == "ctr":
        p = CK_AES_CTR_PARAMS(128, (c_ubyte * 16)(*os.urandom(16)))
        mech, data = Mech(K.CKM_AES_CTR, p), payload(c, 1024)
    elif mode == "gcm":
        iv = ctypes.create_string_buffer(os.urandom(12), 12)
        p = CK_GCM_PARAMS(addressof(iv), 12, 96, None, 0, 128)
        mech, data = Mech(K.CKM_AES_GCM, p), payload(c, 1024)
        mech.pin(iv)

        def refresh():  # fresh IV per encryption, as a real application would
            ctypes.memmove(iv, os.urandom(12), 12)
    else:
        raise SystemExit("Unknown -aesmode")
    return enc_dec_steps(w, mech, key, key, data, refresh)


def b_aescmac(w):
    bits = _aes_bits(w.cfg)
    key = w.shared("aes_mac", lambda: w.add_secret(SecretGen(
        w.lib, w.h, K.CKM_AES_KEY_GEN, aes_items(w, bits, sign=True, verify=True)), "AES-%d" % bits))
    return sign_verify_steps(w, Mech(K.CKM_AES_CMAC), key, key, payload(w.cfg))


def b_hmac(w):
    c = w.cfg
    hn = "sha256" if c["hash"] == "none" else c["hash"]
    nbytes = (c["key"] or 256) // 8
    items = [(K.CKA_CLASS, K.CKO_SECRET_KEY), (K.CKA_KEY_TYPE, K.CKK_GENERIC_SECRET),
             (K.CKA_VALUE_LEN, nbytes), (K.CKA_TOKEN, w.tok), (K.CKA_LABEL, w.label("_hmac")),
             (K.CKA_PRIVATE, True), (K.CKA_SENSITIVE, True), (K.CKA_EXTRACTABLE, False),
             (K.CKA_SIGN, True), (K.CKA_VERIFY, True)]
    key = w.shared("hmac", lambda: w.add_secret(
        SecretGen(w.lib, w.h, K.CKM_GENERIC_SECRET_KEY_GEN, items), "GENERIC_SECRET-%d" % (nbytes * 8)))
    return sign_verify_steps(w, Mech(hmac_mech(hn)), key, key, payload(c))


def b_aeswrapkwp(w):
    L, h, c = w.lib, w.h, w.cfg
    bits = _aes_bits(c)
    kek = w.shared("kek", lambda: w.add_secret(SecretGen(
        L, h, K.CKM_AES_KEY_GEN, aes_items(w, bits, "_kek", wrap=True, unwrap=True)),
        "AES-%d (KEK)" % bits))
    target = w.shared("wrap_target", lambda: w.add_secret(SecretGen(
        L, h, K.CKM_AES_KEY_GEN, aes_items(w, 256, "_target", encrypt=True, decrypt=True,
                                           extractable=True)), "AES-256 (wrap target)"))
    mech = Mech(K.CKM_AES_KEY_WRAP_PAD)
    cap = 512
    wb, wl = ctypes.create_string_buffer(cap), CK_ULONG(cap)
    ut = Tmpl([(K.CKA_CLASS, K.CKO_SECRET_KEY), (K.CKA_KEY_TYPE, K.CKK_AES), (K.CKA_TOKEN, False),
               (K.CKA_SENSITIVE, True), (K.CKA_EXTRACTABLE, True), (K.CKA_ENCRYPT, True),
               (K.CKA_DECRYPT, True)])
    out = CK_ULONG()

    def do_wrap():
        wl.value = cap
        rv = L.C_WrapKey(h, mech.ref, kek, target, wb, byref(wl))
        if rv:
            raise P11Error("C_WrapKey", rv)

    def do_unwrap():
        rv = L.C_UnwrapKey(h, mech.ref, kek, wb, wl.value, ut.arr, ut.n, byref(out))
        if rv:
            raise P11Error("C_UnwrapKey", rv)
        k = out.value
        return lambda: L.C_DestroyObject(h, k)

    do_wrap()
    do_unwrap()()
    w.note = "Unwrapped keys are session keys, destroyed after each unwrap (untimed)."
    steps = []
    if not c["nowrap"]:
        steps.append(("wrap", do_wrap))
    if not c["nounwrap"]:
        steps.append(("unwrap", do_unwrap))
    return steps


def b_digest(w):
    L, h, c = w.lib, w.h, w.cfg
    hn = "sha256" if c["hash"] == "none" else c["hash"]
    mech = Mech(hash_mech(hn))
    data = payload(c, 1024)
    db, dl = ctypes.create_string_buffer(data, len(data)), len(data)
    ob, ol = ctypes.create_string_buffer(64), CK_ULONG(64)

    def do():
        rv = L.C_DigestInit(h, mech.ref)
        if rv:
            raise P11Error("C_DigestInit", rv)
        ol.value = 64
        rv = L.C_Digest(h, db, dl, ob, byref(ol))
        if rv:
            raise P11Error("C_Digest", rv)
    do()
    return [("digest", do)]


def b_rand(w):
    L, h = w.lib, w.h
    n = w.cfg["packet"] or 32
    buf = ctypes.create_string_buffer(n)

    def do():
        rv = L.C_GenerateRandom(h, buf, n)
        if rv:
            raise P11Error("C_GenerateRandom", rv)
    do()
    return [("random", do)]


def b_openclosesession(w):
    L, slot = w.lib, w.slot
    hs = CK_ULONG()
    flags = K.CKF_SERIAL_SESSION | K.CKF_RW_SESSION

    def do():
        rv = L.C_OpenSession(slot, flags, None, None, byref(hs))
        if rv:
            raise P11Error("C_OpenSession", rv)
        rv = L.C_CloseSession(hs.value)
        if rv:
            raise P11Error("C_CloseSession", rv)
    return [("open+close", do)]


# ---- PQC ------------------------------------------------------------------
def _pset(cfg, table, default):
    p = str(cfg["param"] or default).lower().replace("ml-dsa-", "").replace("ml-kem-", "") \
        .replace("slh-dsa-", "")
    if p not in table:
        raise SystemExit("Unknown -param '%s'. Choose: %s" % (cfg["param"], ", ".join(table)))
    return p, table[p]


def _mldsa_gen(w):
    pn, ps = _pset(w.cfg, ML_DSA_SETS, "65")
    g = KeyPairGen(w.lib, w.h, K.CKM_ML_DSA_KEY_PAIR_GEN,
                   pqc_candidates(w, K.CKK_ML_DSA, ps, [K.CKA_VERIFY], [K.CKA_SIGN], "_mldsa"))
    return g, "ML-DSA-%s" % pn


def _slhdsa_gen(w):
    pn, ps = _pset(w.cfg, SLH_DSA_SETS, "sha2-128f")
    g = KeyPairGen(w.lib, w.h, K.CKM_SLH_DSA_KEY_PAIR_GEN,
                   pqc_candidates(w, K.CKK_SLH_DSA, ps, [K.CKA_VERIFY], [K.CKA_SIGN], "_slhdsa"))
    return g, "SLH-DSA-%s" % pn.upper()


def _mlkem_gen(w):
    pn, ps = _pset(w.cfg, ML_KEM_SETS, "768")
    g = KeyPairGen(w.lib, w.h, K.CKM_ML_KEM_KEY_PAIR_GEN,
                   pqc_candidates(w, K.CKK_ML_KEM, ps, [K.CKA_ENCAPSULATE], [K.CKA_DECAPSULATE],
                                  "_mlkem"))
    return g, "ML-KEM-%s" % pn


def b_mldsakeygen(w):
    g, d = _mldsa_gen(w)
    _drop_probe(w, g)
    return keygen_step(w, g.gen, d)


def b_mldsasigver(w):
    pub, prv = w.shared("mldsa", lambda: w.add_pair(*_mldsa_gen(w)))
    return sign_verify_steps(w, Mech(K.CKM_ML_DSA), prv, pub, payload(w.cfg))


def b_slhdsakeygen(w):
    g, d = _slhdsa_gen(w)
    _drop_probe(w, g)
    return keygen_step(w, g.gen, d)


def b_slhdsasigver(w):
    pub, prv = w.shared("slhdsa", lambda: w.add_pair(*_slhdsa_gen(w)))
    return sign_verify_steps(w, Mech(K.CKM_SLH_DSA), prv, pub, payload(w.cfg))


def b_mlkemkeygen(w):
    g, d = _mlkem_gen(w)
    _drop_probe(w, g)
    return keygen_step(w, g.gen, d)


def b_mlkemencap(w):
    L, h, c = w.lib, w.h, w.cfg
    if not L.C_EncapsulateKey:
        raise SystemExit("This Primus P11 library does not expose C_EncapsulateKey "
                         "(needs provider >= 2.6.2 / PKCS#11 v3.2).")
    pname, _ = _pset(c, ML_KEM_SETS, "768")
    pub, prv = w.shared("mlkem", lambda: w.add_pair(*_mlkem_gen(w)))
    mech = Mech(K.CKM_ML_KEM)
    full = [(K.CKA_CLASS, K.CKO_SECRET_KEY), (K.CKA_KEY_TYPE, K.CKK_AES), (K.CKA_VALUE_LEN, 32),
            (K.CKA_TOKEN, False), (K.CKA_SENSITIVE, True), (K.CKA_EXTRACTABLE, False),
            (K.CKA_ENCRYPT, True), (K.CKA_DECRYPT, True)]
    cap = ML_KEM_CT[pname] + 64
    ct, cl = ctypes.create_string_buffer(cap), CK_ULONG(cap)
    out = CK_ULONG()
    E, D = L.C_EncapsulateKey, L.C_DecapsulateKey

    last = None
    for t in (Tmpl(full), Tmpl(full).without({K.CKA_VALUE_LEN}),
              Tmpl([x for x in full if x[0] != K.CKA_VALUE_LEN and x[0] != K.CKA_KEY_TYPE]
                   + [(K.CKA_KEY_TYPE, K.CKK_GENERIC_SECRET)])):
        cl.value = cap
        rv = E(h, mech.ref, pub, t.arr, t.n, ct, byref(cl), byref(out))
        if rv == 0:
            tmpl = t
            L.C_DestroyObject(h, out.value)
            break
        last = rv
    else:
        raise P11Error("C_EncapsulateKey", last)
    ct_len = cl.value

    def do_encap():
        cl.value = cap
        rv = E(h, mech.ref, pub, tmpl.arr, tmpl.n, ct, byref(cl), byref(out))
        if rv:
            raise P11Error("C_EncapsulateKey", rv)
        k = out.value
        return lambda: L.C_DestroyObject(h, k)

    def do_decap():
        rv = D(h, mech.ref, prv, tmpl.arr, tmpl.n, ct, ct_len, byref(out))
        if rv:
            raise P11Error("C_DecapsulateKey", rv)
        k = out.value
        return lambda: L.C_DestroyObject(h, k)

    do_decap()()
    w.sig_len = ct_len
    w.note = ("Shared secrets from encap/decap are session keys, destroyed after each call "
              "(untimed). Ciphertext %d bytes." % ct_len)
    steps = []
    if not c["noenc"]:
        steps.append(("encapsulate", do_encap))
    if not c["nodec"]:
        steps.append(("decapsulate", do_decap))
    return steps


MODES = {
    # name: (builder, description)
    "rsakeygen": (b_rsakeygen, "RSA key pair generation (-k bits)"),
    "rsasigver": (b_rsasigver, "RSA PKCS#1 v1.5 sign/verify (-k, -hash)"),
    "rsapsssigver": (b_rsapsssigver, "RSA-PSS sign/verify (-k, -hash)"),
    "rsaoaepenc": (b_rsaoaepenc, "RSA-OAEP encrypt/decrypt (-k, -hash)"),
    "eckeygen": (b_eckeygen, "EC key pair generation (-c curve)"),
    "ecdsasigver": (b_ecdsasigver, "ECDSA sign/verify (-c, -hash)"),
    "ecdhderive": (b_ecdhderive, "ECDH key derivation (-c)"),
    "eddsakeygen": (b_eddsakeygen, "EdDSA key pair generation (-c ed25519|ed448)"),
    "eddsasigver": (b_eddsasigver, "EdDSA sign/verify (-c ed25519|ed448)"),
    "aeskeygen": (b_aeskeygen, "AES key generation (-k 128|192|256)"),
    "aesenc": (b_aesenc, "AES encrypt/decrypt (-aesmode ecb|cbc|cbcpad|ctr|gcm, -p)"),
    "aescmac": (b_aescmac, "AES-CMAC sign/verify (-k, -p)"),
    "aeswrapkwp": (b_aeswrapkwp, "AES key wrap with padding, wrap/unwrap AES-256 key"),
    "hmac": (b_hmac, "HMAC sign/verify (-hash, -k key bits, -p)"),
    "digest": (b_digest, "Hash on HSM (-hash, -p)"),
    "rand": (b_rand, "Random generation (-p bytes)"),
    "openclosesession": (b_openclosesession, "Open + close session"),
    "mldsakeygen": (b_mldsakeygen, "ML-DSA key pair generation (-param 44|65|87)"),
    "mldsasigver": (b_mldsasigver, "ML-DSA sign/verify (-param 44|65|87)"),
    "slhdsakeygen": (b_slhdsakeygen, "SLH-DSA key pair generation (-param sha2-128f ...)"),
    "slhdsasigver": (b_slhdsasigver, "SLH-DSA sign/verify (-param sha2-128f ...)"),
    "mlkemkeygen": (b_mlkemkeygen, "ML-KEM key pair generation (-param 512|768|1024)"),
    "mlkemencap": (b_mlkemencap, "ML-KEM encapsulate/decapsulate (-param 512|768|1024)"),
}


def mode_mechs(cfg):
    """Mechanisms a test will use - checked against the slot before the run."""
    m, hn = cfg["mode"], cfg["hash"]
    try:
        if m == "rsakeygen":
            return [K.CKM_RSA_PKCS_KEY_PAIR_GEN]
        if m == "rsasigver":
            return [K.CKM_RSA_PKCS_KEY_PAIR_GEN, rsa_pkcs_mech(hn)]
        if m == "rsapsssigver":
            return [K.CKM_RSA_PKCS_KEY_PAIR_GEN, rsa_pss_mech(hn)]
        if m == "rsaoaepenc":
            return [K.CKM_RSA_PKCS_KEY_PAIR_GEN, K.CKM_RSA_PKCS_OAEP, hash_mech(_oaep_hash(cfg))]
        if m == "eckeygen":
            return [K.CKM_EC_KEY_PAIR_GEN]
        if m == "ecdsasigver":
            return [K.CKM_EC_KEY_PAIR_GEN, ecdsa_mech(hn)]
        if m == "ecdhderive":
            return [K.CKM_EC_KEY_PAIR_GEN, K.CKM_ECDH1_DERIVE]
        if m == "eddsakeygen":
            return [K.CKM_EC_EDWARDS_KEY_PAIR_GEN]
        if m == "eddsasigver":
            return [K.CKM_EC_EDWARDS_KEY_PAIR_GEN, K.CKM_EDDSA]
        if m == "aeskeygen":
            return [K.CKM_AES_KEY_GEN]
        if m == "aesenc":
            return [K.CKM_AES_KEY_GEN, {"ecb": K.CKM_AES_ECB, "cbc": K.CKM_AES_CBC,
                                        "cbcpad": K.CKM_AES_CBC_PAD, "ctr": K.CKM_AES_CTR,
                                        "gcm": K.CKM_AES_GCM}[cfg["aesmode"]]]
        if m == "aescmac":
            return [K.CKM_AES_KEY_GEN, K.CKM_AES_CMAC]
        if m == "aeswrapkwp":
            return [K.CKM_AES_KEY_GEN, K.CKM_AES_KEY_WRAP_PAD]
        if m == "hmac":
            return [K.CKM_GENERIC_SECRET_KEY_GEN, hmac_mech("sha256" if hn == "none" else hn)]
        if m == "digest":
            return [hash_mech("sha256" if hn == "none" else hn)]
        if m.startswith("mldsa"):
            return [K.CKM_ML_DSA_KEY_PAIR_GEN] + ([K.CKM_ML_DSA] if "sigver" in m else [])
        if m.startswith("slhdsa"):
            return [K.CKM_SLH_DSA_KEY_PAIR_GEN] + ([K.CKM_SLH_DSA] if "sigver" in m else [])
        if m.startswith("mlkem"):
            return [K.CKM_ML_KEM_KEY_PAIR_GEN] + ([K.CKM_ML_KEM] if "encap" in m else [])
    except KeyError:
        pass
    return []


# Suites: run several tests back-to-back and print one comparison table.
SUITES = {
    "keygen": [
        ("rsakeygen", {"key": 2048}), ("rsakeygen", {"key": 3072}), ("rsakeygen", {"key": 4096}),
        ("eckeygen", {"curve": "p256"}), ("eckeygen", {"curve": "p384"}),
        ("eckeygen", {"curve": "secp256k1"}), ("eddsakeygen", {"curve": "ed25519"}),
        ("aeskeygen", {"key": 256}),
        ("mldsakeygen", {"param": "44"}), ("mldsakeygen", {"param": "65"}),
        ("mldsakeygen", {"param": "87"}), ("slhdsakeygen", {"param": "sha2-128f"}),
        ("slhdsakeygen", {"param": "sha2-128s"}),
        ("mlkemkeygen", {"param": "512"}), ("mlkemkeygen", {"param": "768"}),
        ("mlkemkeygen", {"param": "1024"}),
    ],
    "pqc": [
        ("mldsasigver", {"param": "44"}), ("mldsasigver", {"param": "65"}),
        ("mldsasigver", {"param": "87"}),
        ("slhdsasigver", {"param": "sha2-128f"}), ("slhdsasigver", {"param": "shake-128f"}),
        ("slhdsasigver", {"param": "sha2-192f"}), ("slhdsasigver", {"param": "sha2-256f"}),
        ("mlkemencap", {"param": "512"}), ("mlkemencap", {"param": "768"}),
        ("mlkemencap", {"param": "1024"}),
        ("mldsakeygen", {"param": "65"}), ("mlkemkeygen", {"param": "768"}),
    ],
    "classic": [
        ("rsasigver", {"key": 2048}), ("rsasigver", {"key": 3072}), ("rsasigver", {"key": 4096}),
        ("rsapsssigver", {"key": 2048}), ("rsaoaepenc", {"key": 2048}),
        ("ecdsasigver", {"curve": "p256"}), ("ecdsasigver", {"curve": "p384"}),
        ("ecdsasigver", {"curve": "secp256k1"}), ("eddsasigver", {"curve": "ed25519"}),
        ("ecdhderive", {"curve": "p256"}),
        ("aesenc", {"aesmode": "gcm"}), ("aesenc", {"aesmode": "cbc"}), ("aescmac", {}),
        ("hmac", {}), ("aeswrapkwp", {}), ("digest", {}), ("rand", {}),
    ],
}
SUITES["pqc-vs-classic"] = [
    ("rsasigver", {"key": 2048}), ("rsasigver", {"key": 3072}),
    ("ecdsasigver", {"curve": "p256"}), ("ecdsasigver", {"curve": "p384"}),
    ("eddsasigver", {"curve": "ed25519"}),
    ("mldsasigver", {"param": "44"}), ("mldsasigver", {"param": "65"}),
    ("mldsasigver", {"param": "87"}), ("slhdsasigver", {"param": "sha2-128f"}),
    ("ecdhderive", {"curve": "p256"}), ("mlkemencap", {"param": "768"}),
]
SUITES["all"] = SUITES["classic"] + SUITES["pqc"] + SUITES["keygen"]


def variant_str(ov):
    return " ".join("%s=%s" % (k, v) for k, v in ov.items())


# --------------------------------------------------------------------------
# Worker threads and process groups
# --------------------------------------------------------------------------
class Stat:
    __slots__ = ("count", "total", "lat")

    def __init__(self):
        self.count, self.total, self.lat = 0, 0.0, []


class ThreadRun:
    def __init__(self, idx, slot):
        self.idx, self.slot = idx, slot
        self.stats = {}
        self.error = None
        self.t0 = self.t1 = 0.0
        self.extra = ""
        self.keys, self.deleted = [], []
        self.setup_ms = 0.0
        self.note = ""

    def ops(self):
        return sum(s.count for s in self.stats.values())


def thread_main(lib, cfg, tr, ready, go, stop, tag, share=None, done=None):
    h = None
    w = None
    steps = []
    ts = time.perf_counter()
    try:
        h = open_session(lib, tr.slot, cfg["pin"])
        w = W(lib, h, tr.slot, cfg, tag, share)
        steps = MODES[cfg["mode"]][0](w)
        if w.sig_len:
            tr.extra = ("ciphertext=%dB" if cfg["mode"] == "mlkemencap" else "sig=%dB") % w.sig_len
        for label, _ in steps:
            tr.stats[label] = Stat()
    except BaseException as e:  # report setup failures
        tr.error = "setup: %s" % e
        steps = []
    tr.setup_ms = (time.perf_counter() - ts) * 1000.0
    if w:
        tr.keys = [dict(k) for k in w.keys]
        tr.note = w.note
    try:
        ready.wait()
    except threading.BrokenBarrierError:
        pass
    if tr.error:
        _wait_all(done)
        tr.deleted = _cleanup(lib, h, w, cfg)
        return
    go.wait()
    iters = cfg["iterations"]
    pc = time.perf_counter
    stats = [(tr.stats[l], f) for l, f in steps]
    cycles = 0
    tr.t0 = pc()
    try:
        while not stop.is_set():
            for st, fn in stats:
                t = pc()
                post = fn()
                dt = pc() - t
                if post:
                    post()
                st.count += 1
                st.total += dt
                if len(st.lat) < MAX_SAMPLES:
                    st.lat.append(dt)
                elif random.random() < 0.05:
                    st.lat[random.randrange(MAX_SAMPLES)] = dt
            cycles += 1
            if iters and cycles >= iters:
                break
    except BaseException as e:
        tr.error = str(e)
        stop.set()
    tr.t1 = pc()
    _wait_all(done)   # shared keys may only be deleted once every thread has stopped
    tr.deleted = _cleanup(lib, h, w, cfg)


def _wait_all(done):
    if done is None:
        return
    try:
        done.wait(timeout=600)
    except threading.BrokenBarrierError:
        pass


def _cleanup(lib, h, w, cfg):
    """Destroy every registered test key; return per-key status + delete time."""
    out = []
    if h is None:
        return out
    if w:
        for k in w.keys:
            d = dict(k)
            if cfg["nodestroy"]:
                d["status"], d["dms"] = "kept (-nodestroy)", 0.0
            else:
                t = time.perf_counter()
                rv = lib.C_DestroyObject(h, k["h"])
                d["dms"] = (time.perf_counter() - t) * 1000.0
                d["status"] = "deleted" if rv == 0 else "FAILED 0x%X %s" % (rv, ckr_name(rv))
            out.append(d)
    lib.C_CloseSession(h)
    return out


def group_main(cfg, slots, gidx, counters, msgq, go_evt, stop_evt):
    """Runs in a child process: one library instance, len(slots) threads."""
    for name, val in cfg["consts"].items():
        setattr(K, name, val)
    try:
        lib = Lib(cfg["lib"])
    except BaseException as e:
        msgq.put(("fatal", gidx, "library load: %s" % e))
        return
    runs = [ThreadRun(gidx * 100000 + i, s) for i, s in enumerate(slots)]
    ready = threading.Barrier(len(runs) + 1)
    go, stop = threading.Event(), threading.Event()
    shared = cfg["_shared"]
    share = KeyShare() if shared else None
    done = threading.Barrier(len(runs)) if shared else None
    threads = [threading.Thread(target=thread_main, daemon=True,
                                args=(lib, cfg, tr, ready, go, stop,
                                      "%d_%d_%d" % (os.getpid(), gidx, i), share, done))
               for i, tr in enumerate(runs)]
    for t in threads:
        t.start()
    ready.wait()
    msgq.put(("ready", gidx, [{"slot": tr.slot, "error": tr.error, "keys": tr.keys,
                               "setup_ms": tr.setup_ms, "note": tr.note} for tr in runs]))
    try:
        while not go_evt.wait(0.1):
            if stop_evt.is_set():
                break
        go.set()
        while any(t.is_alive() for t in threads):
            for i, tr in enumerate(runs):
                counters[gidx * cfg["_maxthr"] + i] = tr.ops()
            if stop_evt.is_set() or stop.is_set():
                stop.set()
                stop_evt.set()
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop.set()
    for t in threads:
        t.join()
    for i, tr in enumerate(runs):
        counters[gidx * cfg["_maxthr"] + i] = tr.ops()
    result = []
    for tr in runs:
        result.append({"slot": tr.slot, "error": tr.error, "elapsed": max(tr.t1 - tr.t0, 1e-9),
                       "extra": tr.extra, "deleted": tr.deleted,
                       "stats": {l: (s.count, s.total, s.lat) for l, s in tr.stats.items()}})
    msgq.put(("result", gidx, result))
    lib.finalize()


# --------------------------------------------------------------------------
# HSM latency: PKCS#11 round trip through the Primus provider
# --------------------------------------------------------------------------
def lat_str(v):
    if not v:
        return "n/a"
    v = sorted(v)
    return "min %.3f / avg %.3f / max %.3f ms (%d)" % (v[0], sum(v) / len(v), v[-1], len(v))


def hsm_latency(lib, slots, pin):
    """Round-trip latency (client + network + HSM) before the benchmark starts."""
    print("\nHSM latency (PKCS#11 round trip)")
    # PKCS#11 round trip via the provider (includes client, network and HSM time)
    for slot in slots:
        try:
            t = time.perf_counter()
            h = open_session(lib, slot, pin)
            login_ms = (time.perf_counter() - t) * 1000.0
            buf = ctypes.create_string_buffer(16)
            for _ in range(3):
                lib.C_GenerateRandom(h, buf, 16)
            rnd = []
            for _ in range(30):
                t = time.perf_counter()
                ck("C_GenerateRandom", lib.C_GenerateRandom(h, buf, 16))
                rnd.append((time.perf_counter() - t) * 1000.0)
            ses = []
            for _ in range(10):
                t = time.perf_counter()
                h2 = CK_ULONG()
                ck("C_OpenSession", lib.C_OpenSession(slot, K.CKF_SERIAL_SESSION | K.CKF_RW_SESSION,
                                                      None, None, byref(h2)))
                lib.C_CloseSession(h2.value)
                ses.append((time.perf_counter() - t) * 1000.0)
            lib.C_CloseSession(h)
            print("  PKCS#11 slot %-3d: open+login %.1f ms" % (slot, login_ms))
            print("    round trip    : C_GenerateRandom(16B) %s" % lat_str(rnd))
            print("    session       : C_OpenSession+Close   %s" % lat_str(ses))
        except P11Error as e:
            print("  PKCS#11 slot %-3d: %s" % (slot, e))


# --------------------------------------------------------------------------
# Printing helpers
# --------------------------------------------------------------------------
MECH_FLAGS = [(0x1, "HW"), (0x100, "ENC"), (0x200, "DEC"), (0x400, "DIGEST"), (0x800, "SIGN"),
              (0x2000, "VERIFY"), (0x8000, "GEN"), (0x10000, "GEN_KEYPAIR"), (0x20000, "WRAP"),
              (0x40000, "UNWRAP"), (0x80000, "DERIVE")]


def flag_str(f):
    names = [n for b, n in MECH_FLAGS if f & b]
    rest = f & ~sum(b for b, _ in MECH_FLAGS)
    if rest:
        names.append("0x%X" % rest)
    return "|".join(names)


_MECH_CACHE = {}


def print_mechanisms(lib, slot, cfg):
    mechs = mode_mechs(cfg)
    if not mechs:
        return
    if slot not in _MECH_CACHE:
        try:
            _MECH_CACHE[slot] = {m: (lo, hi, fl) for m, lo, hi, fl in lib.mechanisms(slot)}
        except P11Error:
            _MECH_CACHE[slot] = None
    table, names = _MECH_CACHE[slot], mech_names()
    print("Mechanisms used (slot %d):" % slot)
    for m in mechs:
        n = names.get(m, "0x%X" % m)
        if table is None:
            print("  %-26s (mechanism list unavailable)" % n)
        elif m in table:
            lo, hi, fl = table[m]
            size = ("key %d-%d" % (lo, hi)) if (lo or hi) else ""
            print("  %-26s SUPPORTED     %-14s %s" % (n, size, flag_str(fl)))
        else:
            print("  %-26s NOT REPORTED by slot (test may fail)" % n)


def print_system():
    print("Client  : %s %s | Python %s %s | %d CPUs | host %s" % (
        platform.system(), platform.release(), platform.python_version(),
        platform.architecture()[0], os.cpu_count() or 0, platform.node()))


def _print_limited(lines, verbose, limit=40):
    if verbose or len(lines) <= limit:
        for l in lines:
            print(l)
    else:
        for l in lines[:limit // 2]:
            print(l)
        print("  ... %d more line(s) hidden (use -v to show all) ..." % (len(lines) - limit // 2))


def print_created_keys(threads, cfg, verbose):
    rows, gen = [], {}
    for i, t in enumerate(threads):
        for k in t["keys"]:
            rows.append("  %3d  %4d  0x%08X  %-7s  %-7s  %-24s %-36s %9.1f" % (
                i, t["slot"], k["h"], k["cls"], "session" if cfg["session"] else "token",
                k["desc"][:24], k["label"][:36], k["ms"]))
            if k["cls"] != "public":          # count a pair once
                gen.setdefault(k["desc"], []).append(k["ms"])
    notes = sorted(set(t["note"] for t in threads if t.get("note")))
    print("\nKeys created on the HSM for this test")
    if cfg.get("_shared") and rows:
        per_slot = {}
        for t in threads:
            per_slot[t["slot"]] = per_slot.get(t["slot"], 0) + 1
        procs = max(1, min(cfg["procs"], len(threads)))
        print("  Key mode: SHARED - one key set per slot%s, used by all threads (%s)" % (
            " per process" if procs > 1 else "",
            ", ".join("slot %d: %d threads" % kv for kv in sorted(per_slot.items()))))
    elif rows:
        print("  Key mode: PER THREAD - every thread uses its own key set")
    if rows:
        print("  thr  slot  handle      class    storage  key                      "
              "label                                gen ms")
        _print_limited(rows, verbose)
        print("\nKey creation performance (setup):")
        print("  %-26s %6s %10s %10s %10s %12s" % ("key", "count", "min ms", "avg ms", "max ms",
                                                 "keys/s/thr"))
        for d, v in gen.items():
            avg = sum(v) / len(v)
            print("  %-26s %6d %10.1f %10.1f %10.1f %12.2f" % (d, len(v), min(v), avg, max(v),
                                                             1000.0 / avg if avg else 0))
    else:
        print("  (no persistent test keys for this mode)")
    for n in notes:
        print("  note: " + n)
    setup = [t["setup_ms"] for t in threads]
    if setup:
        print("  thread setup time: min %.1f / avg %.1f / max %.1f ms" % (
            min(setup), sum(setup) / len(setup), max(setup)))


def print_deleted_keys(threads, verbose):
    rows, ok, fail, kept, dms = [], 0, 0, 0, []
    for i, t in enumerate(threads):
        for d in t.get("deleted", []):
            rows.append("  %3d  %4d  0x%08X  %-7s  %-24s %-36s %-18s %7.1f" % (
                i, t["slot"], d["h"], d["cls"], d["desc"][:24], d["label"][:36],
                d["status"][:18], d["dms"]))
            if d["status"] == "deleted":
                ok += 1
                dms.append(d["dms"])
            elif d["status"].startswith("kept"):
                kept += 1
            else:
                fail += 1
    if not rows:
        return
    print("\nTest keys after the run")
    print("  thr  slot  handle      class    key                      "
          "label                                status             del ms")
    _print_limited(rows, verbose)
    extra = ""
    if dms:
        extra = "  |  delete time min %.1f / avg %.1f / max %.1f ms" % (
            min(dms), sum(dms) / len(dms), max(dms))
    print("  deleted %d, failed %d, kept %d%s" % (ok, fail, kept, extra))
    if fail:
        print("  Some keys could not be deleted: run  -cleanup -s <slot>  to remove leftovers.")


# --------------------------------------------------------------------------
# CLI helpers
# --------------------------------------------------------------------------
def parse_x_list(s):
    """'0x8,1X4' -> [(0,8),(1,4)]  |  'PART1x4' -> [('PART1',4)]"""
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        i = max(part.rfind("x"), part.rfind("X"))
        if i <= 0:
            raise SystemExit("Bad thread spec '%s' (expected <slot>x<threads>)" % part)
        out.append((part[:i], int(part[i + 1:])))
    return out


def build_thread_slots(args, lib):
    slots = []
    if args.slots:
        slots += [int(x) for x in args.slots.split(",") if x.strip()]
    if args.nslots:
        for s, n in parse_x_list(args.nslots):
            slots += [int(s)] * n
    if args.ntokennames:
        labels = {cstr(lib.token_info(s).label): s for s in lib.slots()}
        for name, n in parse_x_list(args.ntokennames):
            if name not in labels:
                raise SystemExit("Token/partition '%s' not found. Available: %s"
                                 % (name, ", ".join(labels)))
            slots += [labels[name]] * n
    if not slots:
        raise SystemExit("Specify slots/threads with -s, -ns or -nt (see -h).")
    return slots


def fmt_ver(v):
    return "%d.%d" % (v.major, v.minor)


def print_header(lib, slots):
    i = lib.info()
    print("=" * 100)
    print("%s v%s - Securosys Primus PKCS#11 benchmark   %s" % (
        TOOL_NAME, TOOL_VERSION, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print_system()
    print("Library : %s" % lib.path)
    print("Provider: %s / %s  lib v%s  Cryptoki v%s" % (
        cstr(i.manufacturerID), cstr(i.libraryDescription), fmt_ver(i.libraryVersion),
        fmt_ver(i.cryptokiVersion)))
    print("KEM API : %s" % (lib.kem_source or "not available (ML-KEM encap/decap disabled)"))
    for s in sorted(set(slots)):
        t = lib.token_info(s)
        print("Slot %-4d: partition '%s'  model %s  serial %s  FW %s  threads %d" % (
            s, cstr(t.label), cstr(t.model), cstr(t.serialNumber), fmt_ver(t.firmwareVersion),
            slots.count(s)))
    print("=" * 100)


def cmd_list(lib):
    i = lib.info()
    print_system()
    print("Library : %s" % lib.path)
    print("Provider: %s / %s  lib v%s  Cryptoki v%s" % (
        cstr(i.manufacturerID), cstr(i.libraryDescription), fmt_ver(i.libraryVersion),
        fmt_ver(i.cryptokiVersion)))
    print("KEM API : %s" % (lib.kem_source or "not available"))
    for s in lib.slots():
        t = lib.token_info(s)
        print("  slot %-4d label '%s'  model %s  serial %s  FW %s  sessions %d/%d" % (
            s, cstr(t.label), cstr(t.model), cstr(t.serialNumber), fmt_ver(t.firmwareVersion),
            t.ulSessionCount if t.ulSessionCount < 2 ** 31 else 0,
            t.ulMaxSessionCount if t.ulMaxSessionCount < 2 ** 31 else 0))


def cmd_mechs(lib, slot):
    names = mech_names()
    mechs = lib.mechanisms(slot)
    print("Slot %d supports %d mechanisms:" % (slot, len(mechs)))
    have = set()
    for m, lo, hi, fl in sorted(mechs):
        n = names.get(m, "")
        have.add(n)
        print("  0x%08X  %-30s key %6d-%-6d %s" % (m, n or "(not in tool table)", lo, hi,
                                                 flag_str(fl)))
    print("\nPQC mechanisms used by this tool:")
    for n in PQC_MECHS:
        print("  %-26s 0x%08X  %s" % (n, getattr(K, n), "SUPPORTED" if n in have else "not reported"))


def cmd_cleanup(lib, slot, pin):
    h = open_session(lib, slot, pin)
    ck("C_FindObjectsInit", lib.C_FindObjectsInit(h, None, 0))
    objs, buf, n = [], (CK_ULONG * 256)(), CK_ULONG()
    while True:
        ck("C_FindObjects", lib.C_FindObjects(h, buf, 256, byref(n)))
        if n.value == 0:
            break
        objs += list(buf[:n.value])
    lib.C_FindObjectsFinal(h)
    removed = 0
    for o in objs:
        try:
            lbl = get_attr(lib, h, o, K.CKA_LABEL).decode("utf-8", "replace")
        except P11Error:
            continue
        if lbl.startswith(LABEL_PREFIX):
            rv = lib.C_DestroyObject(h, o)
            print("  %s  0x%08X  %s" % ("deleted" if rv == 0 else "FAILED ", o, lbl))
            removed += rv == 0
    lib.C_CloseSession(h)
    print("Slot %d: removed %d leftover '%s*' objects." % (slot, removed, LABEL_PREFIX))


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    k = min(len(sorted_vals) - 1, max(0, int(round(p / 100.0 * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def build_parser():
    ap = argparse.ArgumentParser(
        prog=TOOL_NAME, allow_abbrev=False, formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Multi-threaded PKCS#11 benchmark for Securosys Primus HSM / CloudHSM.",
        epilog="Modes:\n" + "\n".join("  %-17s %s" % (k, v[1]) for k, v in MODES.items()) +
               "\n\nSuites (-suite): " + ", ".join(SUITES) +
               "\nSLH-DSA -param: " + ", ".join(SLH_DSA_SETS) +
               "\nCurves: " + ", ".join(list(CURVES) + list(ED_CURVES)))
    a = ap.add_argument
    a("-m", "-mode", dest="mode", choices=sorted(MODES), help="benchmark mode")
    a("-suite", dest="suite", choices=sorted(SUITES), help="run a set of tests back-to-back")
    a("-lib", dest="lib", help="path to primusP11.dll / libprimusP11.so (or env PRIMUS_P11_LIB)")
    a("-pwd", "-password", dest="pin", help="partition PKCS#11 PIN (or env PRIMUS_P11_PIN; prompted if absent)")
    a("-s", "-slots", dest="slots", help="slot list, one thread per entry, e.g. 0,0,1")
    a("-ns", "-nslots", dest="nslots", help="slot x threads, e.g. 0x8,1x4")
    a("-nt", "-ntokennames", dest="ntokennames", help="partition label x threads, e.g. PART1x8")
    a("-procs", dest="procs", type=int, default=1, help="worker processes (spread threads, avoids GIL)")
    a("-t", "-timed", dest="timed", type=float, default=0,
      help="run each test for N seconds (default 30, suites 10)")
    a("-i", "-iterations", dest="iterations", type=int, default=0, help="loops per thread instead of -t")
    a("-k", "-key", dest="key", type=int, default=0, help="key size in bits (RSA/AES/HMAC)")
    a("-c", "-curve", dest="curve", help="EC/Edwards curve (default p256 / ed25519)")
    a("-param", dest="param", help="PQC parameter set: ML-DSA 44|65|87, ML-KEM 512|768|1024, SLH-DSA name")
    a("-hash", dest="hash", default="sha256", choices=["none", "sha1", "sha224", "sha256", "sha384",
                                                       "sha512", "sha3-256", "sha3-384", "sha3-512"])
    a("-aesmode", dest="aesmode", default="gcm", choices=["ecb", "cbc", "cbcpad", "ctr", "gcm"])
    a("-p", "-packet", dest="packet", type=int, default=0, help="data size in bytes")
    a("-ses", "-session", dest="session", action="store_true", help="use session objects instead of token objects")
    a("-nos", "-nosign", dest="nosign", action="store_true", help="measure verify only")
    a("-nov", "-noverify", dest="noverify", action="store_true", help="measure sign only")
    a("-noe", "-noenc", dest="noenc", action="store_true", help="measure decrypt/decapsulate only")
    a("-nod", "-nodec", dest="nodec", action="store_true", help="measure encrypt/encapsulate only")
    a("-now", "-nowrap", dest="nowrap", action="store_true", help="measure unwrap only")
    a("-nou", "-nounwrap", dest="nounwrap", action="store_true", help="measure wrap only")
    a("-nvr", "-noverifyr", dest="noverifyr", action="store_true", help="skip decrypt result check")
    a("-ptk", "-perthreadkey", dest="perthreadkey", action="store_true",
      help="give every thread its own key(s) instead of one shared key set per slot")
    a("-n", "-nodestroy", dest="nodestroy", action="store_true", help="leave test keys on the HSM")
    a("-v", "-verbose", dest="verbose", action="store_true", help="show every thread and every key")
    a("-scr", "-scroll", dest="scroll", action="store_true", help="scroll live output instead of overwriting")
    a("-interval", dest="interval", type=float, default=1.0, help="live output interval (s)")
    a("-csv", dest="csv", help="append summary rows to this CSV file")
    a("-nolatency", dest="nolatency", action="store_true", help="skip the HSM latency check")
    a("-latency", dest="do_latency", action="store_true", help="only run the HSM latency check")
    a("-const", dest="consts", action="append", default=[], metavar="NAME=VAL",
      help="override a PKCS#11 constant, e.g. -const CKM_ML_DSA=0x1d")
    a("-list", dest="do_list", action="store_true", help="list slots/partitions and exit")
    a("-mechs", dest="do_mechs", action="store_true", help="list mechanisms of -s slots and exit")
    a("-cleanup", dest="do_cleanup", action="store_true",
      help="delete leftover %s* objects on -s slots and exit" % LABEL_PREFIX)
    a("-version", action="version", version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    return ap


# --------------------------------------------------------------------------
# Running one test
# --------------------------------------------------------------------------
def run_mode(cfg, thread_slots, args):
    """Spawn worker processes for one test. Returns (rows, error_text, interrupted)."""
    procs = max(1, min(cfg["procs"], len(thread_slots)))
    groups = [thread_slots[i::procs] for i in range(procs)]
    cfg = dict(cfg, _maxthr=max(len(g) for g in groups))
    timed = cfg["timed"]

    ctx = mp.get_context("spawn")
    counters = ctx.Array("d", procs * cfg["_maxthr"], lock=False)
    msgq, go_evt, stop_evt = ctx.Queue(), ctx.Event(), ctx.Event()
    workers = [ctx.Process(target=group_main, args=(cfg, g, i, counters, msgq, go_evt, stop_evt))
               for i, g in enumerate(groups)]
    for p in workers:
        p.start()

    print("\nSetting up %d thread(s) in %d process(es) ..." % (len(thread_slots), procs))
    setup_errors, ready_info, results = [], {}, {}
    interrupted = False
    try:
        while len(ready_info) < procs:
            kind, gi, pl = msgq.get()
            if kind == "fatal":
                setup_errors.append(pl)
                ready_info[gi] = []
                results[gi] = []
            elif kind == "ready":
                ready_info[gi] = pl
                setup_errors += [t["error"] for t in pl if t["error"]]
        tinfo = [t for gi in sorted(ready_info) for t in ready_info[gi]]
        print_created_keys(tinfo, cfg, args.verbose)

        if setup_errors:
            print("\nSetup failed:")
            for e in sorted(set(setup_errors)):
                print("  " + e)
            if cfg["mode"].startswith(("mldsa", "slhdsa", "mlkem")) and \
                    any("MECHANISM_INVALID" in e or "ATTRIBUTE" in e for e in setup_errors):
                print("\nHint: PQC needs Primus PKCS#11 Provider >= 2.6.2 and HSM firmware >= 3.1.\n"
                      "      Run '-mechs -s <slot>' to see what the partition reports, and compare the\n"
                      "      CKM_/CKA_ values with 'Primus P11\\include\\pkcs11t.h' (override with -const).")
            stop_evt.set()
            go_evt.set()
            _collect(msgq, results, procs, 30)
            for p in workers:
                p.join(10)
            print_deleted_keys([t for gi in sorted(results) for t in results[gi]], args.verbose)
            return [], sorted(set(setup_errors))[0], False

        print("\nRunning %s ... (Ctrl+C to stop)" % ("%.0f s" % timed if timed else
                                                     "%d iterations/thread" % cfg["iterations"]))
        go_evt.set()
        t0 = time.perf_counter()
        last_ops, last_t = 0.0, t0
        while len(results) < procs:
            try:
                kind, gi, pl = msgq.get(timeout=cfg["interval"])
                if kind == "result":
                    results[gi] = pl
                continue
            except queue.Empty:
                pass
            now = time.perf_counter()
            ops = sum(counters)
            rate = (ops - last_ops) / max(now - last_t, 1e-9)
            last_ops, last_t = ops, now
            line = "  t=%6.1fs  ops=%10d  current %10.1f ops/s  avg %10.1f ops/s" % (
                now - t0, ops, rate, ops / max(now - t0, 1e-9))
            sys.stdout.write(line + ("\n" if cfg["scroll"] else "\r"))
            sys.stdout.flush()
            if timed and now - t0 >= timed:
                stop_evt.set()
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrupted - stopping workers and deleting test keys ...")
        stop_evt.set()
        go_evt.set()
        _collect(msgq, results, procs, 60)
    for p in workers:
        p.join(10)
    threads = [t for gi in sorted(results) for t in results[gi]]
    rows = report(args, cfg, threads, thread_slots)
    print_deleted_keys(threads, args.verbose)
    print("=" * 100)
    errs = [t["error"] for t in threads if t["error"]]
    return rows, (errs[0] if errs else None), interrupted


def _collect(msgq, results, procs, timeout):
    deadline = time.time() + timeout
    while len(results) < procs and time.time() < deadline:
        try:
            kind, gi, pl = msgq.get(timeout=1)
            if kind == "result":
                results[gi] = pl
            elif kind == "fatal":
                results[gi] = []
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            pass


def report(args, cfg, threads, thread_slots):
    if not threads:
        print("\nNo results.")
        return []
    print("\n")
    errors = [t["error"] for t in threads if t["error"]]
    labels = []
    for t in threads:
        for l in t["stats"]:
            if l not in labels:
                labels.append(l)
    if args.verbose or len(threads) <= 2:
        print("Per-thread results:")
        for i, t in enumerate(threads):
            parts = ["%s %.1f/s" % (l, c / t["elapsed"]) for l, (c, _, _) in t["stats"].items()]
            print("  thread %3d slot %-3d %s%s" % (i, t["slot"], "  ".join(parts),
                                                  ("  ERROR: " + t["error"]) if t["error"] else ""))
    else:
        for name, t in (("first", threads[0]), ("last", threads[-1])):
            parts = ["%s %.1f/s" % (l, c / t["elapsed"]) for l, (c, _, _) in t["stats"].items()]
            print("  %s thread: slot %d  %s" % (name, t["slot"], "  ".join(parts)))
    extra = next((t["extra"] for t in threads if t["extra"]), "")
    elapsed = max(t["elapsed"] for t in threads)
    print("\nResults  mode=%s %s threads=%d procs=%d run=%.1fs %s" % (
        cfg["mode"], cfg.get("_variant", ""), len(threads), cfg["procs"], elapsed, extra))
    print("  %-12s %12s %12s %10s %10s %10s %10s %10s" % (
        "operation", "total ops", "ops/s", "avg ms", "min ms", "p50 ms", "p95 ms", "p99 ms"))
    rows = []
    for l in labels:
        cnt = sum(t["stats"].get(l, (0, 0, []))[0] for t in threads)
        tot = sum(t["stats"].get(l, (0, 0, []))[1] for t in threads)
        rate = sum(t["stats"][l][0] / t["elapsed"] for t in threads if l in t["stats"])
        lat = sorted(x for t in threads for x in t["stats"].get(l, (0, 0, []))[2])
        avg = (tot / cnt * 1000) if cnt else 0
        row = (l, cnt, rate, avg, (lat[0] * 1000 if lat else 0), pct(lat, 50) * 1000,
               pct(lat, 95) * 1000, pct(lat, 99) * 1000)
        rows.append(row)
        print("  %-12s %12d %12.1f %10.3f %10.3f %10.3f %10.3f %10.3f" % row)
    if errors:
        print("\nErrors (%d thread(s)):" % len(errors))
        for e in sorted(set(errors)):
            print("  " + e)
    if args.csv:
        new = not os.path.exists(args.csv)
        with open(args.csv, "a", newline="") as f:
            wr = csv.writer(f)
            if new:
                wr.writerow(["timestamp", "mode", "key", "curve", "param", "hash", "aesmode",
                             "packet", "threads", "procs", "slots", "operation", "total_ops",
                             "ops_per_s", "avg_ms", "min_ms", "p50_ms", "p95_ms", "p99_ms",
                             "errors"])
            for r in rows:
                wr.writerow([datetime.datetime.now().isoformat(timespec="seconds"), cfg["mode"],
                             cfg["key"], cfg["curve"], cfg["param"], cfg["hash"], cfg["aesmode"],
                             cfg["packet"], len(threads), cfg["procs"],
                             "|".join(map(str, sorted(set(thread_slots)))),
                             r[0], r[1], "%.1f" % r[2], "%.3f" % r[3], "%.3f" % r[4],
                             "%.3f" % r[5], "%.3f" % r[6], "%.3f" % r[7], len(errors)])
        print("Results appended to %s" % args.csv)
    return rows


def print_suite_summary(name, results):
    print("\n" + "#" * 100)
    print("Suite '%s' summary" % name)
    print("  %-16s %-20s %-12s %12s %10s %10s  %s" % ("mode", "variant", "operation", "ops/s",
                                                     "avg ms", "p95 ms", "status"))
    for mode, ov, rows, err in results:
        v = variant_str(ov)
        if not rows:
            print("  %-16s %-20s %-12s %12s %10s %10s  %s" % (mode, v, "-", "-", "-", "-",
                                                             "SKIPPED: " + (err or "no result")[:60]))
            continue
        for r in rows:
            print("  %-16s %-20s %-12s %12.1f %10.3f %10.3f  %s" % (
                mode, v, r[0], r[2], r[3], r[6], "ok" if not err else "ERR: " + err[:50]))
    print("#" * 100)


def main():
    args = build_parser().parse_args()
    consts = {}
    for c in args.consts:
        n, _, v = c.partition("=")
        if not hasattr(K, n.strip()):
            raise SystemExit("Unknown constant '%s'" % n)
        consts[n.strip()] = int(v, 0)
        setattr(K, n.strip(), consts[n.strip()])

    lib = Lib(args.lib)
    if args.do_list:
        cmd_list(lib)
        return
    pin = args.pin or os.environ.get("PRIMUS_P11_PIN")
    if args.do_mechs:
        for s in ([int(x) for x in args.slots.split(",")] if args.slots else lib.slots()):
            cmd_mechs(lib, s)
        return
    if pin is None:
        pin = getpass.getpass("Partition PIN: ")
    if args.do_cleanup:
        for s in ([int(x) for x in args.slots.split(",")] if args.slots else lib.slots()):
            cmd_cleanup(lib, s, pin)
        return

    thread_slots = build_thread_slots(args, lib)
    print_header(lib, thread_slots)
    if args.do_latency or not args.nolatency:
        hsm_latency(lib, sorted(set(thread_slots)), pin)
    if args.do_latency:
        return
    if not args.mode and not args.suite:
        raise SystemExit("Specify -mode or -suite (see -h).")

    base = dict(vars(args))
    base.update(pin=pin, lib=lib.path, consts=consts)
    for k in ("do_list", "do_mechs", "do_cleanup", "do_latency", "suite"):
        base.pop(k, None)
    base["_shared"] = not (args.perthreadkey or args.session)
    if args.session and not args.perthreadkey:
        print("\nNote: -session objects cannot be shared between sessions; "
              "using one key set per thread.")
    base["timed"] = args.timed or (0 if args.iterations else (10.0 if args.suite else 30.0))

    plan = SUITES[args.suite] if args.suite else [(args.mode, {})]
    suite_results = []
    for n, (mode, ov) in enumerate(plan, 1):
        cfg = dict(base, mode=mode, **ov)
        cfg["_variant"] = variant_str(ov)
        title = "%s %s" % (mode, cfg["_variant"])
        if args.suite:
            title = "[%d/%d] %s" % (n, len(plan), title)
        print("\n" + "-" * 100)
        print("TEST %s   threads=%d  %s" % (title, len(thread_slots), MODES[mode][1]))
        print_mechanisms(lib, sorted(set(thread_slots))[0], cfg)
        rows, err, interrupted = run_mode(cfg, thread_slots, args)
        suite_results.append((mode, ov, rows, err))
        if interrupted:
            break
    if args.suite:
        print_suite_summary(args.suite, suite_results)
    lib.finalize()


if __name__ == "__main__":
    mp.freeze_support()
    main()
