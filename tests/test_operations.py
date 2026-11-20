import os
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from test_checkpoint import LEDGER


class OperationsTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.file = self.root / "document"
        self.file.write_bytes(b"initial payload")
        self.run_ledger("append", self.file)

    def run_ledger(self, *args, db="ledger.db", success=True):
        result = subprocess.run(
            [sys.executable, str(LEDGER), "--db", db, *map(str, args)],
            cwd=self.root, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        return result.stdout.strip()

    def test_extension_and_fingerprint_migration(self):
        self.run_ledger("keygen", "--key-file", "ledger.key")
        key = ("--key-file", "ledger.key")
        token = self.run_ledger("checkpoint", *key)
        auth = ("--checkpoint", token, *key)
        self.file.write_bytes(b"x" * (2 * 1024 * 1024))
        self.run_ledger("append", "--hash-only", self.file)
        self.run_ledger("verify", *auth, success=False)
        result = self.run_ledger("verify", *auth, "--allow-extension", "--file", self.file)
        self.assertIn("blocks=2", result)
        self.run_ledger("append", self.file, success=False)
        with sqlite3.connect(self.root / "ledger.db") as db:
            self.assertEqual(db.execute("SELECT kind, length(payload) FROM blocks").fetchall(),
                             [(0, 15), (1, 32)])
            db.execute("UPDATE blocks SET kind=0 WHERE height=1")
        self.run_ledger("verify", *auth, "--allow-extension", success=False)

    def test_signed_checkpoint_backup_and_restore(self):
        openssl = os.environ.get("LEDGER_OPENSSL", "openssl")
        result = subprocess.run([openssl, "version"], capture_output=True, text=True)
        if not result.stdout.startswith("OpenSSL 3."):
            self.skipTest("OpenSSL 3 richiesto")
        self.run_ledger("keygen", "--private-key", "ledger.private.der")
        self.run_ledger("export-public", "--private-key", "ledger.private.der",
                        "--public-key", "ledger.public.der")
        token = self.run_ledger("checkpoint", "--private-key", "ledger.private.der")
        auth = ("--signed-checkpoint", token, "--public-key", "ledger.public.der")
        altered = token[:-2] + ("00" if token[-2:] != "00" else "01")
        self.run_ledger("verify", "--signed-checkpoint", altered,
                        "--public-key", "ledger.public.der", success=False)
        self.run_ledger("backup", "backup.db", *auth)
        self.run_ledger("backup", "backup.db", *auth, success=False)
        self.run_ledger("restore", "backup.db", *auth, db="restored.db")
        self.run_ledger("verify", *auth, db="restored.db")
        with sqlite3.connect(self.root / "backup.db") as db:
            db.execute("DELETE FROM blocks")
        self.run_ledger("restore", "backup.db", *auth, db="rejected.db", success=False)
        self.assertFalse((self.root / "rejected.db").exists())
