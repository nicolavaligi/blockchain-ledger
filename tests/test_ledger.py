import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from ledger import MAX_PAYLOAD, SCHEMA, append, block_hash, verify


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute(SCHEMA)

    def test_hash_format(self):
        import hashlib

        raw = b"blockchain-ledger:v1\0" + bytes(7) + b"\x01"
        raw += bytes(7) + b"\x02" + bytes(32) + b"abc"
        self.assertEqual(block_hash(1, 2, bytes(32), b"abc"), hashlib.sha256(raw).digest())

    def test_empty_and_multiple_batches(self):
        self.assertEqual(verify(self.db), (0, None))
        self.assertEqual(append(self.db, [b""])[0], 0)
        height, tip = append(self.db, [b"two", b"three"])
        self.assertEqual(height, 2)
        self.assertEqual(verify(self.db, tip), (3, tip))

    def test_invalid_batch_rolls_back(self):
        with self.assertRaises(ValueError):
            append(self.db, [b"valid", bytes(MAX_PAYLOAD + 1)])
        self.assertEqual(verify(self.db), (0, None))
        self.assertEqual(append(self.db, [bytes(MAX_PAYLOAD)])[0], 0)

    def test_tampering(self):
        append(self.db, [b"original", b"next"])
        self.db.execute("UPDATE blocks SET payload = ? WHERE height = 0", (b"edited",))
        with self.assertRaisesRegex(ValueError, "posizione 0"):
            verify(self.db)

    def test_truncation_with_checkpoint(self):
        append(self.db, [b"first"])
        _, tip = append(self.db, [b"second"])
        self.db.execute("DELETE FROM blocks WHERE height = 1")
        with self.assertRaisesRegex(ValueError, "checkpoint"):
            verify(self.db, tip)

    def test_concurrent_batches(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.db"
            with closing(sqlite3.connect(path)) as db:
                db.execute(SCHEMA)

            def write(value):
                with closing(sqlite3.connect(path)) as db:
                    return append(db, [bytes([value])] * 3)[0]

            with ThreadPoolExecutor(max_workers=4) as pool:
                self.assertEqual(sorted(pool.map(write, range(8))), list(range(2, 24, 3)))
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(verify(db)[0], 24)


if __name__ == "__main__":
    unittest.main()
