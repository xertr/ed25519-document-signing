#!/usr/bin/env python3
"""Ed25519 document signing and verification tool (Project 4).

Library: `cryptography` (OpenSSL-backed Ed25519, RFC 8032).

Commands:
  keygen  --name NAME [--key-dir DIR]          generate keypair; private key is
                                               passphrase-encrypted, public key is PEM
  sign    --key PRIV.pem --doc FILE --sig OUT  sign raw bytes of FILE, write base64 signature
  verify  --doc FILE --sig SIG --pubkey PUB.pem [--fingerprint HEX]
                                               verify; optionally pin the key fingerprint

Exit codes (verify): 0 = VALID, 1 = INVALID SIGNATURE, 2 = MALFORMED INPUT,
                     3 = FILE NOT FOUND, 4 = UNTRUSTED KEY (fingerprint mismatch)
The passphrase is read from env var SIGN_PASSPHRASE, or prompted if unset.
"""
import argparse
import base64
import binascii
import getpass
import hashlib
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_KEY_DIR = os.path.expanduser("~/project4_private_keys")  # OUTSIDE the repo

# result codes
VALID, INVALID, MALFORMED, NOT_FOUND, UNTRUSTED = 0, 1, 2, 3, 4


def fingerprint(public_key: Ed25519PublicKey) -> str:
    """SHA-256 over the raw 32-byte public key, hex, grouped for humans."""
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    h = hashlib.sha256(raw).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, len(h), 4))


def _norm_fp(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").strip().lower()


def _passphrase() -> bytes:
    pw = os.environ.get("SIGN_PASSPHRASE") or getpass.getpass("Key passphrase: ")
    return pw.encode()


def generate_keypair(name: str, key_dir: str = DEFAULT_KEY_DIR, pub_dir: str = "."):
    os.makedirs(key_dir, mode=0o700, exist_ok=True)
    priv = Ed25519PrivateKey.generate()  # OS CSPRNG
    priv_path = os.path.join(key_dir, f"{name}_private.pem")
    pub_path = os.path.join(pub_dir, f"{name}_public.pem")
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_passphrase()),
    )
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = priv.public_key()
    with open(pub_path, "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.SubjectPublicKeyInfo))
    fp = fingerprint(pub)
    with open(os.path.join(pub_dir, f"{name}_public.fingerprint"), "w") as f:
        f.write(fp + "\n")
    return priv_path, pub_path, fp


def sign_file(key_path: str, doc_path: str, sig_path: str) -> str:
    with open(key_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=_passphrase())
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    with open(doc_path, "rb") as f:  # raw bytes: no newline translation
        data = f.read()
    sig = priv.sign(data)
    with open(sig_path, "wb") as f:
        f.write(base64.b64encode(sig) + b"\n")
    return fingerprint(priv.public_key())


def verify_files(doc_path, sig_path, pub_path, expected_fp=None):
    """Return (code, message). Never raises on bad input."""
    # 1. read files
    try:
        with open(doc_path, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            sig_b64 = f.read()
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
    except FileNotFoundError as e:
        return NOT_FOUND, f"FILE NOT FOUND: {e.filename}"
    except OSError as e:
        return NOT_FOUND, f"CANNOT READ FILE: {e}"

    # 2. parse public key
    try:
        pub = serialization.load_pem_public_key(pub_pem)
        if not isinstance(pub, Ed25519PublicKey):
            return MALFORMED, "MALFORMED PUBLIC KEY: not an Ed25519 key"
    except (ValueError, TypeError, Exception) as e:  # noqa: BLE001
        return MALFORMED, f"MALFORMED PUBLIC KEY: could not parse PEM ({type(e).__name__})"
    fp = fingerprint(pub)

    # 3. optional key pinning (trust decision) BEFORE trusting the result
    if expected_fp is not None and _norm_fp(expected_fp) != _norm_fp(fp):
        return UNTRUSTED, (
            "UNTRUSTED KEY: fingerprint mismatch\n"
            f"  expected: {expected_fp.strip()}\n"
            f"  presented: {fp}")

    # 4. parse signature
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return MALFORMED, "MALFORMED SIGNATURE: not valid base64"
    if len(sig) != 64:
        return MALFORMED, f"MALFORMED SIGNATURE: expected 64 bytes, got {len(sig)}"

    # 5. cryptographic check
    try:
        pub.verify(sig, data)
    except InvalidSignature:
        return INVALID, "INVALID SIGNATURE: signature does not match document and key"
    pinned = "key matches pinned fingerprint" if expected_fp else "key NOT authenticated (no fingerprint pinned)"
    return VALID, f"VALID: signature verifies under key {fp}\n  ({pinned})"


def main(argv=None):
    p = argparse.ArgumentParser(description="Ed25519 document signing/verification")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--name", required=True)
    k.add_argument("--key-dir", default=DEFAULT_KEY_DIR); k.add_argument("--pub-dir", default=".")
    s = sub.add_parser("sign"); s.add_argument("--key", required=True)
    s.add_argument("--doc", required=True); s.add_argument("--sig", required=True)
    v = sub.add_parser("verify"); v.add_argument("--doc", required=True)
    v.add_argument("--sig", required=True); v.add_argument("--pubkey", required=True)
    v.add_argument("--fingerprint", help="expected SHA-256 key fingerprint (hex, colons optional)")
    a = p.parse_args(argv)

    try:
        if a.cmd == "keygen":
            priv, pub, fp = generate_keypair(a.name, a.key_dir, a.pub_dir)
            print(f"Private key (encrypted, mode 600): {priv}")
            print(f"Public key: {pub}")
            print(f"SHA-256 fingerprint: {fp}")
            return 0
        if a.cmd == "sign":
            fp = sign_file(a.key, a.doc, a.sig)
            print(f"Signed {a.doc} -> {a.sig}")
            print(f"Signer key fingerprint: {fp}")
            return 0
        code, msg = verify_files(a.doc, a.sig, a.pubkey, a.fingerprint)
        print(msg)
        return code
    except FileNotFoundError as e:
        print(f"FILE NOT FOUND: {e.filename}"); return NOT_FOUND
    except (ValueError, TypeError) as e:
        print(f"ERROR: {e} (wrong passphrase or malformed key file?)"); return MALFORMED


if __name__ == "__main__":
    sys.exit(main())
