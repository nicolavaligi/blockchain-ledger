"""A local hash-linked ledger backed by SQLite."""

import argparse
import hashlib
import sqlite3
import struct
import sys
import time
from contextlib import closing
from pathlib import Path

import checkpoint

GENESIS_PARENT = bytes(32)
MAX_PAYLOAD = 1024 * 1024
SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY CHECK (height >= 0),
    created_ns INTEGER NOT NULL CHECK (created_ns >= 0),
    parent BLOB NOT NULL CHECK (length(parent) = 32),
    payload BLOB NOT NULL CHECK (length(payload) <= 1048576),
    digest BLOB NOT NULL CHECK (length(digest) = 32)
)
"""


def block_hash(height, created_ns, parent, payload):
    digest = hashlib.sha256(b"blockchain-ledger:v1\0")
    digest.update(struct.pack(">QQ", height, created_ns))
    digest.update(parent)
    digest.update(payload)
    return digest.digest()


def append(db, payloads):
    """Atomically append a batch and return its final height and digest."""
    db.execute("BEGIN IMMEDIATE")
    with db:
        tip = db.execute(
            "SELECT height, digest FROM blocks ORDER BY height DESC LIMIT 1"
        ).fetchone()
        height, parent = tip if tip else (-1, GENESIS_PARENT)
        added = False
        for payload in payloads:
            if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
                raise ValueError("Il payload deve essere in byte e al massimo di 1 MiB.")
            added = True
            height += 1
            created_ns = time.time_ns()
            digest = block_hash(height, created_ns, parent, payload)
            db.execute(
                "INSERT INTO blocks VALUES (?, ?, ?, ?, ?)",
                (height, created_ns, parent, payload, digest),
            )
            parent = digest
        if not added:
            raise ValueError("Il lotto deve contenere almeno un payload.")
    return height, parent


def verify(db, expected_tip=None):
    """Check one SQLite read snapshot and optionally compare a trusted tip."""
    parent = GENESIS_PARENT
    count = 0
    rows = db.execute(
        "SELECT height, created_ns, parent, payload, digest FROM blocks ORDER BY height"
    )
    with closing(rows):
        for height, created_ns, stored_parent, payload, digest in rows:
            if (
                height != count
                or type(created_ns) is not int
                or created_ns < 0
                or not isinstance(payload, bytes)
                or len(payload) > MAX_PAYLOAD
                or stored_parent != parent
                or digest != block_hash(height, created_ns, parent, payload)
            ):
                raise ValueError(f"Blocco non valido alla posizione {count}.")
            count += 1
            parent = digest
    if expected_tip is not None and (not count or parent != expected_tip):
        raise ValueError("L'hash finale differisce dal checkpoint fidato.")
    return count, parent if count else None


def read_payload(path):
    with open(path, "rb") as stream:
        return stream.read(MAX_PAYLOAD + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="ledger.db")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("append", help="Aggiunge un blocco per file.")
    add.add_argument("files", nargs="+")
    check = commands.add_parser("verify", help="Controlla la catena.")
    expected = check.add_mutually_exclusive_group()
    expected.add_argument("--tip", help="SHA-256 finale salvato separatamente.")
    expected.add_argument("--checkpoint", help="Checkpoint autenticato da verificare.")
    check.add_argument("--key-file", help="File con la chiave del checkpoint.")
    attest = commands.add_parser("checkpoint", help="Autentica lo stato corrente del registro.")
    attest.add_argument("--key-file", required=True)
    keygen = commands.add_parser("keygen", help="Genera una chiave per i checkpoint.")
    keygen.add_argument("--key-file", required=True)
    args = parser.parse_args()
    if args.command == "verify" and (args.checkpoint is None) != (args.key_file is None):
        parser.error("--checkpoint e --key-file devono essere usati insieme.")

    try:
        if args.command == "keygen":
            checkpoint.create_key(args.key_file)
        elif args.command == "append":
            with closing(sqlite3.connect(args.db)) as db:
                db.execute(SCHEMA)
                height, digest = append(db, (read_payload(path) for path in args.files))
            print(f"height={height} tip={digest.hex()}")
        else:
            expected_count = None
            expected_tip = None
            if args.command == "checkpoint":
                key = checkpoint.read_key(args.key_file)
            elif args.checkpoint is not None:
                key = checkpoint.read_key(args.key_file)
                expected_count, expected_tip = checkpoint.unseal(args.checkpoint, key)
            elif args.tip is not None:
                expected_tip = bytes.fromhex(args.tip)
                if len(expected_tip) != 32:
                    raise ValueError("Il checkpoint SHA-256 deve contenere 32 byte.")

            uri = Path(args.db).resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as db:
                count, digest = verify(db, expected_tip)
            if expected_count is not None and expected_count != count:
                raise ValueError("Il numero di blocchi differisce dal checkpoint autenticato.")
            if args.command == "checkpoint":
                print(checkpoint.seal(count, digest, key))
            else:
                print(f"blocks={count} tip={digest.hex() if digest else '-'}")
    except (OSError, ValueError, sqlite3.Error) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
