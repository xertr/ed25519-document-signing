#!/usr/bin/env python3
"""Experiment 4: public-key substitution, controlled simulation.
Alice = legitimate author. Mallory = attacker who controls the distribution channel
(a 'keyserver' directory) and swaps Alice's public key for her own.
Mallory's private key exists only in memory."""
import os, shutil, subprocess, sys, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = os.path.dirname(os.path.abspath(__file__)); os.chdir(ROOT)
log = open("logs/08_exp4_key_substitution.txt", "w")
def say(s=""): print(s); log.write(s + "\n")

def cli_verify(doc, sig, pub, fp=None):
    cmd = [sys.executable, "sign_verify.py", "verify", "--doc", doc, "--sig", sig, "--pubkey", pub]
    if fp: cmd += ["--fingerprint", fp]
    shown = "$ python3 sign_verify.py verify --doc %s --sig %s --pubkey %s%s" % (
        doc, sig, pub, (" --fingerprint \\\n      " + fp) if fp else "")
    p = subprocess.run(cmd, capture_output=True, text=True)
    say(shown); say(p.stdout.rstrip()); say(f"[exit code {p.returncode}]"); say()
    return p.returncode

say("=== Experiment 4: public-key substitution (controlled simulation) ===\n")
shutil.rmtree("attacker", ignore_errors=True); os.makedirs("attacker")
shutil.rmtree("keyserver_sim", ignore_errors=True); os.makedirs("keyserver_sim")

# Out-of-band trusted value: Alice's real fingerprint (e.g. from her business card / in person)
trusted_fp = open("sample/author_public.fingerprint").read().strip()
say(f"Trusted fingerprint of Alice (obtained out of band): {trusted_fp}\n")

say("Step 1. Normal situation: keyserver serves Alice's genuine key")
shutil.copy("sample/author_public.pem", "keyserver_sim/alice_public.pem")
assert cli_verify("sample/document.txt", "sample/document.sig", "keyserver_sim/alice_public.pem") == 0

say("Step 2. Mallory generates her own keypair, forges a document, signs it")
mallory = Ed25519PrivateKey.generate()
forged = (b"SYNTHETIC CERTIFICATE OF COMPLETION\n-----------------------------------\n"
          b"Issued to : Mallory (attacker)\nIssued by : Alice Author\n"
          b"Statement : FORGED - Alice never wrote or signed this document.\n")
open("attacker/forged_document.txt", "wb").write(forged)
open("attacker/forged.sig", "wb").write(base64.b64encode(mallory.sign(forged)) + b"\n")
open("attacker/mallory_public.pem", "wb").write(mallory.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
say("   attacker/forged_document.txt, attacker/forged.sig, attacker/mallory_public.pem created\n")

say("Step 3. Mallory compromises the distribution channel: the keyserver file that")
say("        claims to be 'alice_public.pem' is replaced with Mallory's public key")
shutil.copy("attacker/mallory_public.pem", "keyserver_sim/alice_public.pem")
say()

say("Step 4. VICTIM WITHOUT KEY AUTHENTICATION downloads 'Alice's key' and verifies")
r_naive = cli_verify("attacker/forged_document.txt", "attacker/forged.sig", "keyserver_sim/alice_public.pem")
say("   -> The forgery verifies as VALID. The math is correct; the TRUST is broken.")
say("      A valid signature only proves the signer held the key that was presented.\n")

say("Step 5. DEFENCE: victim pins Alice's fingerprint obtained out of band")
r_def = cli_verify("attacker/forged_document.txt", "attacker/forged.sig",
                   "keyserver_sim/alice_public.pem", fp=trusted_fp)
say("Step 6. DEFENCE, genuine key restored: Alice's real document still verifies when pinned")
shutil.copy("sample/author_public.pem", "keyserver_sim/alice_public.pem")
r_ok = cli_verify("sample/document.txt", "sample/document.sig", "keyserver_sim/alice_public.pem", fp=trusted_fp)

good = (r_naive == 0 and r_def == 4 and r_ok == 0)
say("=== RESULT: " + ("attack succeeds without key authentication; blocked by fingerprint pinning"
                     if good else "UNEXPECTED BEHAVIOUR") + " ===")
log.close(); sys.exit(0 if good else 1)
