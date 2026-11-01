import base64, os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import sign_verify as sv


@pytest.fixture
def setup(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    doc = tmp_path / "d.txt"; doc.write_bytes(b"hello world\n")
    sig = tmp_path / "d.sig"; sig.write_bytes(base64.b64encode(priv.sign(doc.read_bytes())))
    pub = tmp_path / "p.pem"; pub.write_bytes(pub_pem)
    return priv, str(doc), str(sig), str(pub), tmp_path


def test_valid(setup):
    _, d, s, p, _ = setup
    assert sv.verify_files(d, s, p)[0] == sv.VALID

def test_modified_doc(setup):
    _, d, s, p, _ = setup
    open(d, "wb").write(b"hello World\n")
    assert sv.verify_files(d, s, p)[0] == sv.INVALID

def test_wrong_key(setup, tmp_path):
    _, d, s, _, t = setup
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (t / "o.pem").write_bytes(other)
    assert sv.verify_files(d, s, str(t / "o.pem"))[0] == sv.INVALID

@pytest.mark.parametrize("i", [0, 31, 32, 63])
def test_every_region_of_signature_is_checked(setup, i):
    _, d, s, p, _ = setup
    raw = bytearray(base64.b64decode(open(s, "rb").read())); raw[i] ^= 1
    open(s, "wb").write(base64.b64encode(bytes(raw)))
    assert sv.verify_files(d, s, p)[0] == sv.INVALID

def test_truncated_and_garbage_signature(setup):
    _, d, s, p, _ = setup
    open(s, "wb").write(base64.b64encode(b"x" * 63))
    assert sv.verify_files(d, s, p)[0] == sv.MALFORMED
    open(s, "wb").write(b"!!!notbase64")
    assert sv.verify_files(d, s, p)[0] == sv.MALFORMED
    open(s, "wb").write(b"")
    assert sv.verify_files(d, s, p)[0] == sv.MALFORMED

def test_bad_public_key(setup):
    _, d, s, p, _ = setup
    open(p, "wb").write(b"garbage"); assert sv.verify_files(d, s, p)[0] == sv.MALFORMED
    open(p, "wb").write(b"");        assert sv.verify_files(d, s, p)[0] == sv.MALFORMED

def test_missing_files(setup):
    _, d, s, p, _ = setup
    assert sv.verify_files("nope", s, p)[0] == sv.NOT_FOUND

def test_fingerprint_pinning(setup):
    priv, d, s, p, _ = setup
    good = sv.fingerprint(priv.public_key())
    assert sv.verify_files(d, s, p, good)[0] == sv.VALID
    assert sv.verify_files(d, s, p, good.replace(":", "").upper())[0] == sv.VALID  # format-insensitive
    assert sv.verify_files(d, s, p, "00" * 32)[0] == sv.UNTRUSTED

def test_empty_document_signs_and_verifies(tmp_path):
    priv = Ed25519PrivateKey.generate()
    (tmp_path / "e").write_bytes(b""); (tmp_path / "e.sig").write_bytes(base64.b64encode(priv.sign(b"")))
    (tmp_path / "p").write_bytes(priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    assert sv.verify_files(str(tmp_path/"e"), str(tmp_path/"e.sig"), str(tmp_path/"p"))[0] == sv.VALID

def test_line_endings_matter(setup):
    _, d, s, p, _ = setup
    open(d, "wb").write(b"hello world\r\n")
    assert sv.verify_files(d, s, p)[0] == sv.INVALID

def test_keygen_encrypts_private_key_with_600(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGN_PASSPHRASE", "pw")
    priv_path, pub_path, fp = sv.generate_keypair("t", str(tmp_path / "keys"), str(tmp_path))
    assert b"ENCRYPTED PRIVATE KEY" in open(priv_path, "rb").read()
    assert oct(os.stat(priv_path).st_mode & 0o777) == "0o600"
