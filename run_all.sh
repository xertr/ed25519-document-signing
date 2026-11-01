#!/usr/bin/env bash
# Reproduces everything from scratch: new keys, signature, all experiments, tests.
set -e
cd "$(dirname "$0")"
export SIGN_PASSPHRASE="${SIGN_PASSPHRASE:-demo-passphrase-not-a-real-secret}"
KEYDIR="${KEYDIR:-$HOME/project4_private_keys}"
mkdir -p logs
python3 sign_verify.py keygen --name author --key-dir "$KEYDIR" --pub-dir sample | tee logs/01_keygen.txt
python3 sign_verify.py sign --key "$KEYDIR/author_private.pem" --doc sample/document.txt --sig sample/document.sig | tee logs/02_sign.txt
python3 experiments.py
python3 key_substitution_demo.py
python3 -m pytest -q | tee logs/11_pytest.txt
