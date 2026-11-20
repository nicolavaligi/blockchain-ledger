"""Measure batch append and full verification on temporary disk storage."""

import argparse
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from ledger import MAX_PAYLOAD, SCHEMA, append, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blocks", type=int, default=10000)
    parser.add_argument("--bytes", type=int, default=256)
    args = parser.parse_args()
    if args.blocks < 1 or not 0 <= args.bytes <= MAX_PAYLOAD:
        parser.error("Specify a positive block count and a valid payload size.")
    payload = bytes(args.bytes)
    with TemporaryDirectory() as directory:
        with closing(sqlite3.connect(Path(directory) / "bench.db")) as db:
            db.execute(SCHEMA)
            start = perf_counter()
            _, tip = append(db, (payload for _ in range(args.blocks)))
            appended = perf_counter()
            count, _ = verify(db, tip)
            verified = perf_counter()
            if count != args.blocks:
                raise RuntimeError("Unexpected block count.")
    print(f"blocks={count} payload_bytes={args.bytes}")
    print(f"append={count / (appended - start):,.0f} blocks/s")
    print(f"verify={count / (verified - appended):,.0f} blocks/s")


if __name__ == "__main__":
    main()
