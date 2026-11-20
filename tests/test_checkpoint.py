import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from checkpoint import KEY_SIZE, create_key, read_key, seal, unseal

LEDGER = Path(__file__).resolve().parents[1] / "ledger.py"


class CheckpointTest(unittest.TestCase):
    def test_token_authentication(self):
        key = bytes(KEY_SIZE)
        tip = bytes(range(32))
        token = seal(7, tip, key)
        self.assertEqual(unseal(token, key), (7, tip))
        for invalid_token, invalid_key in (
            ("ff" + token[2:], key),
            (token, bytes([1]) * KEY_SIZE),
            (token[:-2], key),
        ):
            with self.subTest(token=invalid_token):
                with self.assertRaises(ValueError):
                    unseal(invalid_token, invalid_key)

    def test_key_creation_does_not_overwrite(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.key"
            create_key(path)
            original = read_key(path)
            with self.assertRaises(FileExistsError):
                create_key(path)
            self.assertEqual(read_key(path), original)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_cli_rejects_valid_replacement_chain(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "ledger.key"
            create_key(key)
            payload = root / "payload"
            payload.write_bytes(b"original")

            def run(db, *args):
                return subprocess.run(
                    [sys.executable, str(LEDGER), "--db", str(root / db), *args],
                    capture_output=True, text=True, check=False,
                )

            self.assertEqual(run("original.db", "append", str(payload)).returncode, 0)
            result = run("original.db", "checkpoint", "--key-file", str(key))
            self.assertEqual(result.returncode, 0, result.stderr)
            options = ("verify", "--checkpoint", result.stdout.strip(), "--key-file", str(key))
            self.assertEqual(run("original.db", *options).returncode, 0)

            payload.write_bytes(b"replacement")
            self.assertEqual(run("replacement.db", "append", str(payload)).returncode, 0)
            self.assertEqual(run("replacement.db", "verify").returncode, 0)
            self.assertEqual(run("replacement.db", *options).returncode, 1)
