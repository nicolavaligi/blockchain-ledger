"""Authenticate a ledger snapshot with a separately stored 256-bit key."""

import hashlib
import hmac
import os
import secrets
import struct

KEY_SIZE = 32
DOMAIN = b"blockchain-ledger:checkpoint:v1\0"
BODY = struct.Struct(">Q32s")
TOKEN_SIZE = BODY.size + KEY_SIZE


def create_key(path):
    key = secrets.token_bytes(KEY_SIZE)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(key)


def read_key(path):
    with open(path, "rb") as stream:
        key = stream.read(KEY_SIZE + 1)
    if len(key) != KEY_SIZE:
        raise ValueError("La chiave deve contenere esattamente 32 byte.")
    return key


def seal(count, tip, key):
    if not count or tip is None:
        raise ValueError("Il registro deve contenere almeno un blocco.")
    body = BODY.pack(count, tip)
    return (body + hmac.digest(key, DOMAIN + body, hashlib.sha256)).hex()


def unseal(token, key):
    if len(token) != 2 * TOKEN_SIZE:
        raise ValueError("Formato del checkpoint non valido.")
    raw = bytes.fromhex(token)
    if len(raw) != TOKEN_SIZE:
        raise ValueError("Formato del checkpoint non valido.")
    body, mac = raw[:BODY.size], raw[BODY.size:]
    if not hmac.compare_digest(mac, hmac.digest(key, DOMAIN + body, hashlib.sha256)):
        raise ValueError("Autenticazione del checkpoint fallita.")
    count, tip = BODY.unpack(body)
    if not count:
        raise ValueError("Il checkpoint deve attestare almeno un blocco.")
    return count, tip
