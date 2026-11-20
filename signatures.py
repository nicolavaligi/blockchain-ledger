"""Ed25519 checkpoints using the OpenSSL 3 command-line tool."""

import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from checkpoint import BODY

DOMAIN = b"blockchain-ledger:ed25519:v1\0"
PRIVATE_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
PUBLIC_PREFIX = bytes.fromhex("302a300506032b6570032100")
SIGNATURE_SIZE = 64


def openssl(*args):
    result = subprocess.run(
        [os.environ.get("LEDGER_OPENSSL", "openssl"), *args],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=False,
    )
    if result.returncode:
        raise ValueError("Operazione Ed25519 fallita. Verifica chiavi, firma e OpenSSL 3.")
    return result.stdout


def generate(private_path):
    key = openssl("genpkey", "-algorithm", "ED25519", "-outform", "DER")
    with open(os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(key)


def export_public(private_path, public_path):
    with TemporaryDirectory() as directory:
        key = validated_key(private_path, PRIVATE_PREFIX, Path(directory))
        public = openssl("pkey", "-in", str(key), "-inform", "DER", "-pubout", "-outform", "DER")
    with open(public_path, "xb") as stream:
        stream.write(public)


def validated_key(path, prefix, directory):
    size = len(prefix) + 32
    with open(path, "rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size or not data.startswith(prefix):
        raise ValueError("Chiave Ed25519 DER non valida.")
    key = directory / "key.der"
    key.write_bytes(data)
    return key


def seal(count, tip, key_path):
    if not count:
        raise ValueError("Il registro deve contenere almeno un blocco.")
    body = BODY.pack(count, tip)
    with TemporaryDirectory() as directory:
        root = Path(directory)
        key = validated_key(key_path, PRIVATE_PREFIX, root)
        message = root / "message"
        message.write_bytes(DOMAIN + body)
        signature = openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(key),
                            "-keyform", "DER", "-in", str(message))
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError("Dimensione firma Ed25519 non valida.")
    return (body + signature).hex()


def unseal(token, key_path):
    size = BODY.size + SIGNATURE_SIZE
    if len(token) != 2 * size:
        raise ValueError("Formato del checkpoint Ed25519 non valido.")
    raw = bytes.fromhex(token)
    if len(raw) != size:
        raise ValueError("Formato del checkpoint Ed25519 non valido.")
    body, signature = raw[:BODY.size], raw[BODY.size:]
    with TemporaryDirectory() as directory:
        root = Path(directory)
        key = validated_key(key_path, PUBLIC_PREFIX, root)
        message, sigfile = root / "message", root / "signature"
        message.write_bytes(DOMAIN + body)
        sigfile.write_bytes(signature)
        openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key),
                "-keyform", "DER", "-in", str(message), "-sigfile", str(sigfile))
    count, tip = BODY.unpack(body)
    if not count:
        raise ValueError("Il checkpoint deve attestare almeno un blocco.")
    return count, tip
