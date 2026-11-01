#!/usr/bin/env python3
"""Runs security experiments 1,2,3,5 + malformed-input tests through the real CLI.
Each run is written to logs/. Only PUBLIC keys are ever written to disk here;
throw-away private keys for the 'wrong key' case live only in memory."""
import os, shutil, subprocess, sys, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
WORK = "experiment_work"
DOC, SIG, PUB = "sample/document.txt", "sample/document.sig", "sample/author_public.pem"
EXPECTED_FP = open("sample/author_public.fingerprint").read().strip()
results = []


def run(label, doc, sig, pub, fp=None, log=None, expect=None):
    cmd = [sys.executable, "sign_verify.py", "verify", "--doc", doc, "--sig", sig, "--pubkey", pub]
    if fp: cmd += ["--fingerprint", fp]
    shown = "$ python3 sign_verify.py verify --doc %s --sig %s --pubkey %s%s" % (
        doc, sig, pub, (" --fingerprint " + fp) if fp else "")
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = f"{shown}\n{p.stdout.rstrip()}\n[exit code {p.returncode}]\n"
    ok = (p.returncode == expect)
    out += f"==> {'AS EXPECTED' if ok else 'UNEXPECTED'} (expected exit {expect})\n"
    results.append((label, ok))
    log.write(f"--- {label} ---\n{out}\n")
    print(f"--- {label} ---\n{out}")


def start(name, title):
    f = open(f"logs/{name}.txt", "w")
    f.write(f"=== {title} ===\n\n"); print(f"\n=== {title} ===\n")
    return f


def write_pub(priv, path):
    with open(path, "wb") as f:
        f.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))


shutil.rmtree(WORK, ignore_errors=True); os.makedirs(WORK)
orig = open(DOC, "rb").read()
orig_sig = base64.b64decode(open(SIG, "rb").read())

# ---- Experiment 5 (baseline, run first) ----
f = start("03_exp5_baseline_first", "Experiment 5: original document, correct key (baseline, run first)")
run("5a original doc + correct key", DOC, SIG, PUB, log=f, expect=0)
run("5b same, with trusted fingerprint pinned", DOC, SIG, PUB, fp=EXPECTED_FP, log=f, expect=0)
f.close()

# ---- Experiment 1: document modification ----
f = start("04_exp1_document_modification", "Experiment 1: document modification")
mod = bytearray(orig); i = orig.index(b"Example Student")
mod[i] = ord("e")  # 'E' -> 'e' : one-character change
open(f"{WORK}/doc_one_char.txt", "wb").write(mod)
f.write(f"Changed byte {i}: 'E' -> 'e' in 'Example Student'\n\n")
run("1a one character changed", f"{WORK}/doc_one_char.txt", SIG, PUB, log=f, expect=1)
bit = bytearray(orig); bit[0] ^= 0x01  # single bit flip
open(f"{WORK}/doc_one_bit.txt", "wb").write(bit)
f.write("Flipped one bit of byte 0\n\n")
run("1b single bit flipped", f"{WORK}/doc_one_bit.txt", SIG, PUB, log=f, expect=1)
open(f"{WORK}/doc_trailing_newline.txt", "wb").write(orig + b"\n")
f.write("Appended one trailing newline\n\n")
run("1c trailing newline added", f"{WORK}/doc_trailing_newline.txt", SIG, PUB, log=f, expect=1)
open(f"{WORK}/doc_crlf.txt", "wb").write(orig.replace(b"\n", b"\r\n"))
f.write("Converted LF line endings to CRLF\n\n")
run("1d CRLF line endings", f"{WORK}/doc_crlf.txt", SIG, PUB, log=f, expect=1)
f.close()

# ---- Experiment 2: wrong public key ----
f = start("05_exp2_wrong_public_key", "Experiment 2: wrong public key")
other = Ed25519PrivateKey.generate(); write_pub(other, f"{WORK}/other_public.pem")
run("2 verify with public key from a different keypair", DOC, SIG, f"{WORK}/other_public.pem", log=f, expect=1)
f.close()

# ---- Experiment 3: signature modification ----
f = start("06_exp3_signature_modification", "Experiment 3: signature modification")
def wsig(name, raw): open(f"{WORK}/{name}", "wb").write(base64.b64encode(raw) + b"\n"); return f"{WORK}/{name}"
b = bytearray(orig_sig); b[10] ^= 0xFF
f.write("Flipped all bits of signature byte 10 (inside R)\n\n")
run("3a byte in R half modified", DOC, wsig("sig_flip_R.sig", b), PUB, log=f, expect=1)
b = bytearray(orig_sig); b[40] ^= 0x01
f.write("Flipped one bit of signature byte 40 (inside S)\n\n")
run("3b bit in S half modified", DOC, wsig("sig_flip_S.sig", b), PUB, log=f, expect=1)
f.write("Truncated signature to 63 bytes\n\n")
run("3c truncated (63 bytes)", DOC, wsig("sig_trunc.sig", orig_sig[:63]), PUB, log=f, expect=2)
f.write("Padded signature to 65 bytes\n\n")
run("3d padded (65 bytes)", DOC, wsig("sig_pad.sig", orig_sig + b"\x00"), PUB, log=f, expect=2)
open(f"{WORK}/sig_garbage.sig", "w").write("this is !!! not base64 @@@\n")
f.write("Replaced signature file with non-base64 text\n\n")
run("3e garbage (not base64)", DOC, f"{WORK}/sig_garbage.sig", PUB, log=f, expect=2)
f.write("Replaced signature with 64 random bytes\n\n")
run("3f random 64-byte signature", DOC, wsig("sig_random.sig", os.urandom(64)), PUB, log=f, expect=1)
f.close()

# ---- malformed inputs ----
f = start("07_malformed_inputs", "Malformed-input handling (must not crash)")
open(f"{WORK}/empty.txt", "wb").close()
run("M1 empty document file", f"{WORK}/empty.txt", SIG, PUB, log=f, expect=1)
open(f"{WORK}/garbage_key.pem", "w").write("-----BEGIN PUBLIC KEY-----\nnot a real key\n-----END PUBLIC KEY-----\n")
run("M2 garbage public key PEM", DOC, SIG, f"{WORK}/garbage_key.pem", log=f, expect=2)
open(f"{WORK}/empty_key.pem", "wb").close()
run("M3 empty public key file", DOC, SIG, f"{WORK}/empty_key.pem", log=f, expect=2)
open(f"{WORK}/empty.sig", "wb").close()
run("M4 empty signature file", DOC, f"{WORK}/empty.sig", PUB, log=f, expect=2)
run("M5 nonexistent document", "no_such_file.txt", SIG, PUB, log=f, expect=3)
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
ec = generate_private_key(SECP256R1()).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
open(f"{WORK}/ec_key.pem", "wb").write(ec)
run("M6 valid PEM but wrong algorithm (P-256)", DOC, SIG, f"{WORK}/ec_key.pem", log=f, expect=2)
f.close()

# ---- experiment 5 again (last) ----
f = start("09_exp5_baseline_last", "Experiment 5 (repeated last): original document still verifies")
run("5c original doc + correct key, after all attacks", DOC, SIG, PUB, fp=EXPECTED_FP, log=f, expect=0)
f.close()

bad = [l for l, ok in results if not ok]
summary = "\n=== SUMMARY ===\n" + "\n".join(f"[{'PASS' if ok else 'FAIL'}] {l}" for l, ok in results)
summary += f"\n\n{len(results) - len(bad)}/{len(results)} cases behaved as expected\n"
open("logs/10_summary.txt", "w").write(summary); print(summary)
sys.exit(1 if bad else 0)
