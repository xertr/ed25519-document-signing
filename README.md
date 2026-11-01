# Project 4: Ed25519 Digital Signature Document Verification

A command-line tool that signs a document with Ed25519 and verifies it under a public key,
plus a test harness for the five required security experiments.

**Library:** [`cryptography`](https://cryptography.io) (OpenSSL-backed Ed25519, RFC 8032). Language: Python 3.9+.

## Setup
```bash
pip install -r requirements.txt
```

## Usage
```bash
export SIGN_PASSPHRASE='choose-a-passphrase'      # or omit to be prompted

# 1. generate keys (private key is passphrase-encrypted, mode 600, stored OUTSIDE the repo)
python3 sign_verify.py keygen --name author --pub-dir sample

# 2. sign (signature saved separately, base64)
python3 sign_verify.py sign --key ~/project4_private_keys/author_private.pem \
        --doc sample/document.txt --sig sample/document.sig

# 3. verify
python3 sign_verify.py verify --doc sample/document.txt --sig sample/document.sig \
        --pubkey sample/author_public.pem

# 3b. verify AND authenticate the key against a trusted fingerprint
python3 sign_verify.py verify --doc sample/document.txt --sig sample/document.sig \
        --pubkey sample/author_public.pem --fingerprint "$(cat sample/author_public.fingerprint)"
```

### Result codes (`verify`)
| Exit | Message | Meaning |
|---|---|---|
| 0 | VALID | signature verifies under the presented key |
| 1 | INVALID SIGNATURE | wrong document, wrong key, or altered signature |
| 2 | MALFORMED ... | unparsable public key, wrong-length or non-base64 signature, wrong key type |
| 3 | FILE NOT FOUND | a file is missing |
| 4 | UNTRUSTED KEY | key fingerprint does not match the pinned, out-of-band value |

The tool never prints a stack trace for bad input.

## Reproduce all experiments
```bash
./run_all.sh                      # new keys, signature, experiments 1-5, malformed inputs, pytest
python3 experiments.py            # experiments 1, 2, 3, 5 + malformed-input cases
python3 key_substitution_demo.py  # experiment 4 (attack + fingerprint-pinning defence)
python3 -m pytest -q              # 14 unit tests
```
Logs are written to `logs/`; screenshots of each log are in `screenshots/`.

## Layout
| Path | Contents |
|---|---|
| `sign_verify.py` | the tool (keygen / sign / verify) |
| `experiments.py` | experiments 1, 2, 3, 5 and malformed-input tests, run through the real CLI |
| `key_substitution_demo.py` | experiment 4: substitution attack and defence |
| `test_sign_verify.py` | pytest unit tests |
| `sample/` | sample document, its signature, public key, fingerprint |
| `attacker/` | Mallory's public key, forged document and signature (simulation only) |
| `logs/` | execution logs for every experiment |

## Key management
* The private key is encrypted with a passphrase (PKCS#8) and written with mode `0600` to
  `~/project4_private_keys/`, outside the project folder.
* `.gitignore` excludes `*.key`, `*private*.pem` and key directories.
* The submission contains **only** public keys and verification artifacts. `logs/12_key_hygiene.txt` shows `git status`
  and a `grep` confirming no private key is present.
* The passphrase in `run_all.sh` is a demo value only; use your own for real keys.

## Notes
* Documents are signed as **raw bytes**. Changing line endings (LF/CRLF) or adding a trailing newline invalidates the
  signature (experiments 1c, 1d).
* A `VALID` result without `--fingerprint` only proves the signer held the private key for the *presented* public key,
  not who that key belongs to (experiment 4).
