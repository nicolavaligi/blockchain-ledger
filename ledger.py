"""A local hash-linked ledger backed by SQLite."""

import argparse
import hashlib
import json
import os
import sqlite3
import struct
import sys
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from subprocess import TimeoutExpired
from tempfile import TemporaryDirectory

import checkpoint
import signatures

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


def block_hash(height, created_ns, parent, payload, kind=0):
    domain = b"blockchain-ledger:file-sha256:v1\0" if kind else b"blockchain-ledger:v1\0"
    digest = hashlib.sha256(domain)
    digest.update(struct.pack(">QQ", height, created_ns))
    digest.update(parent)
    digest.update(payload)
    return digest.digest()


def has_kind(db):
    return any(row[1] == "kind" for row in db.execute("PRAGMA table_info(blocks)"))


def append(db, payloads, *, fingerprints=False):
    """Atomically append a batch and return its final height and digest."""
    db.execute("BEGIN IMMEDIATE")
    with db:
        typed = has_kind(db)
        if fingerprints and not typed:
            db.execute("ALTER TABLE blocks ADD COLUMN kind INTEGER NOT NULL DEFAULT 0 "
                       "CHECK (kind IN (0, 1))")
            typed = True
        tip = db.execute(
            "SELECT height, digest FROM blocks ORDER BY height DESC LIMIT 1"
        ).fetchone()
        height, parent = tip if tip else (-1, GENESIS_PARENT)
        added = False
        for payload in payloads:
            if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
                raise ValueError("Il payload deve essere in byte e al massimo di 1 MiB.")
            if fingerprints and len(payload) != 32:
                raise ValueError("L'impronta deve contenere 32 byte.")
            added = True
            height += 1
            created_ns = time.time_ns()
            digest = block_hash(height, created_ns, parent, payload, fingerprints)
            row = (height, created_ns, parent, payload, digest)
            if typed:
                db.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)", (*row, int(fingerprints)))
            else:
                db.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)", row)
            parent = digest
        if not added:
            raise ValueError("Il lotto deve contenere almeno un payload.")
    return height, parent


def verify(db, expected_tip=None, *, anchor=None, allow_extension=False, fingerprint=None):
    """Check one SQLite read snapshot and optionally compare a trusted tip."""
    parent = GENESIS_PARENT
    count = 0
    kind_column = "kind" if has_kind(db) else "0"
    rows = db.execute(
        f"SELECT height, created_ns, parent, payload, digest, {kind_column} "
        "FROM blocks ORDER BY height"
    )
    found = False
    with closing(rows):
        for height, created_ns, stored_parent, payload, digest, kind in rows:
            if (
                type(height) is not int
                or height != count
                or type(created_ns) is not int
                or created_ns < 0
                or not isinstance(payload, bytes)
                or len(payload) > MAX_PAYLOAD
                or type(kind) is not int
                or kind not in (0, 1)
                or (kind == 1 and len(payload) != 32)
                or stored_parent != parent
                or digest != block_hash(height, created_ns, parent, payload, kind)
            ):
                raise ValueError(f"Blocco non valido alla posizione {count}.")
            count += 1
            parent = digest
            if anchor is not None and count == anchor[0] and digest != anchor[1]:
                raise ValueError("Il prefisso differisce dal checkpoint fidato.")
            if kind == 1 and fingerprint is not None and payload == fingerprint:
                found = True
    if anchor is not None and (count < anchor[0] or (not allow_extension and count != anchor[0])):
        raise ValueError("Il numero di blocchi differisce dal checkpoint fidato.")
    if fingerprint is not None and not found:
        raise ValueError("Impronta assente dal registro.")
    if expected_tip is not None and (not count or parent != expected_tip):
        raise ValueError("L'hash finale differisce dal checkpoint fidato.")
    return count, parent if count else None


def read_only(path):
    db = sqlite3.connect(Path(path).absolute().as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("PRAGMA trusted_schema = OFF")
    except sqlite3.Error:
        db.close()
        raise
    return db


def fingerprint_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(MAX_PAYLOAD), b""):
            digest.update(chunk)
    return digest.digest()


def verified_copy(source, destination, anchor):
    destination = Path(destination).absolute()
    for suffix in ("", "-wal", "-shm", "-journal"):
        if os.path.lexists(str(destination) + suffix):
            raise FileExistsError(f"Destinazione già occupata: {destination}{suffix}")
    with TemporaryDirectory(dir=destination.parent) as directory:
        staging = Path(directory) / "snapshot.db"
        with closing(read_only(source)) as original, closing(sqlite3.connect(staging)) as copied:
            original.backup(copied)
            copied.execute("PRAGMA trusted_schema = OFF")
            copied.execute("PRAGMA journal_mode = DELETE")
            if copied.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError("Controllo di integrità SQLite fallito.")
            result = verify(copied, anchor=anchor)
        staging.chmod(0o600)
        with staging.open("rb") as stream:
            os.fsync(stream.fileno())
        os.link(staging, destination)
    return result


def authentication(parser, *, required=False, include_tip=False):
    tokens = parser.add_mutually_exclusive_group(required=required)
    tokens.add_argument("--checkpoint", help="Checkpoint HMAC.")
    tokens.add_argument("--signed-checkpoint", help="Checkpoint Ed25519.")
    if include_tip:
        tokens.add_argument("--tip", help="SHA-256 finale salvato separatamente.")
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument("--key-file", help="Chiave HMAC.")
    keys.add_argument("--public-key", help="Chiave pubblica Ed25519 DER.")


def get_anchor(parser, args):
    if (args.checkpoint is None) != (args.key_file is None):
        parser.error("--checkpoint e --key-file devono essere usati insieme.")
    if (args.signed_checkpoint is None) != (args.public_key is None):
        parser.error("--signed-checkpoint e --public-key devono essere usati insieme.")
    if args.checkpoint is not None:
        return checkpoint.unseal(args.checkpoint, checkpoint.read_key(args.key_file))
    if args.signed_checkpoint is not None:
        return signatures.unseal(args.signed_checkpoint, args.public_key)
    return None


def read_payload(path):
    with open(path, "rb") as stream:
        return stream.read(MAX_PAYLOAD + 1)


def timestamp(created_ns):
    try:
        moment = datetime.fromtimestamp(created_ns // 10**9, timezone.utc)
    except (OverflowError, ValueError, OSError):
        return f"{created_ns}ns"
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_tip(text):
    if text is None:
        return None
    try:
        tip = bytes.fromhex(text)
    except ValueError:
        tip = b""
    if len(tip) != 32:
        raise ValueError("L'hash finale SHA-256 deve contenere 32 byte esadecimali.")
    return tip


def report(db, args, count, emit):
    """Answer a read command from the snapshot that verify just checked."""
    kind = "kind" if has_kind(db) else "0"
    if args.command == "list":
        first = 0 if args.limit is None else max(count - args.limit, 0)
        rows = db.execute(
            f"SELECT height, created_ns, {kind}, length(payload), digest FROM blocks"
            " WHERE height >= ? ORDER BY height", (first,),
        )
        for height, created_ns, fingerprint, size, digest in rows:
            fields = dict(height=height, created=timestamp(created_ns),
                          kind="sha256" if fingerprint else "payload", bytes=size, digest=digest.hex())
            emit(" ".join(f"{name}={value}" for name, value in fields.items()),
                 created_ns=created_ns, **fields)
    elif args.command == "export":
        row = db.execute("SELECT payload FROM blocks WHERE height = ?", (args.height,)).fetchone()
        if row is None:
            raise ValueError(f"Nessun blocco all'altezza {args.height}.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        with open(os.open(args.output, flags, 0o600), "wb") as stream:
            stream.write(row[0])
        emit(f"height={args.height} bytes={len(row[0])} output={args.output}",
             height=args.height, bytes=len(row[0]), output=args.output)
    else:
        missing = False
        for path in args.files:
            heights = db.execute(
                f"SELECT height FROM blocks WHERE ({kind} = 0 AND payload = ?)"
                f" OR ({kind} = 1 AND payload = ?) ORDER BY height",
                (read_payload(path), fingerprint_file(path)),
            ).fetchall()
            heights = [height for height, in heights]
            emit(f"{path}: " + (" ".join(f"height={height}" for height in heights) or "assente"),
                 file=path, heights=heights)
            missing = missing or not heights
        return 1 if missing else 0
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="ledger.db")
    parser.add_argument("--json", action="store_true", help="Scrive un oggetto JSON per riga.")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("append", help="Aggiunge un blocco per file.")
    add.add_argument("files", nargs="+")
    check = commands.add_parser("verify", help="Controlla la catena.")
    add.add_argument("--hash-only", action="store_true", help="Registra solo SHA-256 dei file.")
    authentication(check, include_tip=True)
    check.add_argument("--allow-extension", action="store_true", help="Accetta blocchi successivi.")
    check.add_argument("--file", help="Cerca l'impronta del file nella catena verificata.")
    attest = commands.add_parser("checkpoint", help="Autentica lo stato corrente del registro.")
    signing = attest.add_mutually_exclusive_group(required=True)
    signing.add_argument("--key-file")
    signing.add_argument("--private-key")
    keygen = commands.add_parser("keygen", help="Genera una chiave per i checkpoint.")
    generation = keygen.add_mutually_exclusive_group(required=True)
    generation.add_argument("--key-file")
    generation.add_argument("--private-key")
    public = commands.add_parser("export-public", help="Esporta la chiave pubblica Ed25519.")
    public.add_argument("--private-key", required=True)
    public.add_argument("--public-key", required=True)
    backup = commands.add_parser("backup", help="Crea una copia verificata in DESTINATION.")
    backup.add_argument("destination")
    restore = commands.add_parser("restore", help="Ripristina BACKUP nel nuovo file --db.")
    restore.add_argument("backup")
    for command in (backup, restore):
        authentication(command, required=True)
    listing = commands.add_parser("list", help="Elenca i blocchi verificati.")
    listing.add_argument("--limit", type=int, help="Mostra solo gli ultimi N blocchi.")
    export = commands.add_parser("export", help="Estrae il payload di un blocco.")
    export.add_argument("height", type=int)
    export.add_argument("--output", required=True, help="File da creare, mai sovrascritto.")
    find = commands.add_parser("find", help="Cerca contenuto o impronta dei file.")
    find.add_argument("files", nargs="+")
    for command in (listing, export, find):
        authentication(command, include_tip=True)
        command.add_argument("--allow-extension", action="store_true", help="Accetta blocchi successivi.")
    args = parser.parse_args(argv)
    if args.command == "list" and args.limit is not None and args.limit < 1:
        parser.error("--limit deve essere un intero positivo.")

    def emit(text, **fields):
        print(json.dumps(fields) if args.json else text)

    try:
        if args.command == "keygen":
            if args.private_key is not None:
                signatures.generate(args.private_key)
            else:
                checkpoint.create_key(args.key_file)
        elif args.command == "export-public":
            signatures.export_public(args.private_key, args.public_key)
        elif args.command == "append":
            load = fingerprint_file if args.hash_only else read_payload
            with closing(sqlite3.connect(args.db)) as db:
                db.execute(SCHEMA)
                height, digest = append(db, (load(path) for path in args.files),
                                        fingerprints=args.hash_only)
            emit(f"height={height} tip={digest.hex()}", height=height, tip=digest.hex())
        elif args.command == "checkpoint":
            with closing(read_only(args.db)) as db:
                db.execute("BEGIN")
                count, digest = verify(db)
            if args.private_key is not None:
                token = signatures.seal(count, digest, args.private_key)
            else:
                token = checkpoint.seal(count, digest, checkpoint.read_key(args.key_file))
            emit(token, checkpoint=token, blocks=count, tip=digest.hex())
        else:
            anchor = get_anchor(parser, args)
            if args.command == "backup":
                count, digest = verified_copy(args.db, args.destination, anchor)
            elif args.command == "restore":
                count, digest = verified_copy(args.backup, args.db, anchor)
            else:
                if args.allow_extension and anchor is None:
                    parser.error("--allow-extension richiede un checkpoint autenticato.")
                tip = parse_tip(args.tip)
                path = getattr(args, "file", None)
                fingerprint = fingerprint_file(path) if path is not None else None
                with closing(read_only(args.db)) as db:
                    db.execute("BEGIN")
                    count, digest = verify(db, tip, anchor=anchor,
                                           allow_extension=args.allow_extension, fingerprint=fingerprint)
                    if args.command != "verify":
                        return report(db, args, count, emit)
                if fingerprint is not None and not args.json:
                    print(f"fingerprint={fingerprint.hex()}")
            fields = dict(blocks=count, tip=digest.hex() if digest else None)
            if args.command == "verify" and fingerprint is not None:
                fields["fingerprint"] = fingerprint.hex()
            emit(f"blocks={count} tip={fields['tip'] or '-'}", **fields)
    except (OSError, ValueError, sqlite3.Error, TimeoutExpired) as error:
        print(json.dumps({"error": str(error)}) if args.json else error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
