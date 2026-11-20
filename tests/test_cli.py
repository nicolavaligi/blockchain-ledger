import io
import json
import os
import sqlite3
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from checkpoint import create_key
from ledger import main
from signatures import generate


class CliTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.key = self.root / "ledger.key"
        create_key(self.key)
        self.first = self.write("first", b"first document")
        self.second = self.write("second", b"second document")
        self.assertEqual(self.run_cli("append", self.first, self.second)[0], 0)

    def write(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return str(path)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(["--db", str(self.root / "ledger.db"), *map(str, args)])
        return status, out.getvalue(), err.getvalue()

    def test_list(self):
        status, out, _ = self.run_cli("list")
        lines = out.splitlines()
        self.assertEqual(status, 0)
        self.assertEqual(len(lines), 2)
        self.assertRegex(lines[0], r"^height=0 created=\d{4}-\d\d-\d\dT[\d:]+Z kind=payload bytes=14 digest=[0-9a-f]{64}$")
        status, out, _ = self.run_cli("list", "--limit", "1")
        self.assertEqual(out.splitlines(), lines[1:])

    def test_export_round_trip_without_overwrite(self):
        output = self.root / "copy"
        self.assertEqual(self.run_cli("export", "1", "--output", output)[0], 0)
        self.assertEqual(output.read_bytes(), b"second document")
        if os.name == "posix":
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.run_cli("export", "0", "--output", output)[0], 1)
        self.assertEqual(output.read_bytes(), b"second document")
        status, _, err = self.run_cli("export", "2", "--output", self.root / "none")
        self.assertEqual(status, 1)
        self.assertIn("altezza 2", err)
        self.assertFalse((self.root / "none").exists())

    def test_find(self):
        self.assertEqual(self.run_cli("append", self.first)[0], 0)
        status, out, _ = self.run_cli("find", self.first)
        self.assertEqual((status, out), (0, f"{self.first}: height=0 height=2\n"))
        absent = self.write("absent", b"never stored")
        status, out, _ = self.run_cli("find", self.second, absent)
        self.assertEqual(status, 1)
        self.assertEqual(out, f"{self.second}: height=1\n{absent}: assente\n")

    def test_find_and_list_fingerprints(self):
        large = self.write("large", bytes(2 * 1024 * 1024))
        self.assertEqual(self.run_cli("find", large)[0], 1)
        self.assertEqual(self.run_cli("append", "--hash-only", large, self.first)[0], 0)
        self.assertEqual(self.run_cli("find", large)[1], f"{large}: height=2\n")
        self.assertEqual(self.run_cli("find", self.first)[1], f"{self.first}: height=0 height=3\n")
        status, out, _ = self.run_cli("list", "--limit", "1")
        self.assertRegex(out, r"^height=3 created=\S+ kind=sha256 bytes=32 digest=[0-9a-f]{64}\n$")

    def test_read_commands_accept_extension_of_checkpoint(self):
        _, token, _ = self.run_cli("checkpoint", "--key-file", self.key)
        options = ("--checkpoint", token.strip(), "--key-file", self.key)
        self.assertEqual(self.run_cli("list", *options)[0], 0)
        self.assertEqual(self.run_cli("append", self.first)[0], 0)
        status, out, err = self.run_cli("list", *options)
        self.assertEqual((status, out), (1, ""))
        self.assertIn("numero di blocchi", err)
        status, out, _ = self.run_cli("list", *options, "--allow-extension")
        self.assertEqual((status, len(out.splitlines())), (0, 3))

    def test_read_commands_refuse_untrusted_state(self):
        for command in (("list",), ("find", self.first), ("export", "0", "--output", self.root / "x")):
            with self.subTest(command=command[0]):
                status, out, err = self.run_cli(*command, "--tip", "00" * 32)
                self.assertEqual((status, out), (1, ""))
                self.assertIn("checkpoint", err)
        self.assertFalse((self.root / "x").exists())

    def test_invalid_trust_arguments(self):
        for tip in ("zz" * 32, "00" * 31):
            status, _, err = self.run_cli("verify", "--tip", tip)
            self.assertEqual(status, 1)
            self.assertIn("32 byte", err)
        status, _, err = self.run_cli("verify", "--checkpoint", "zz" * 72, "--key-file", self.key)
        self.assertEqual(status, 1)
        self.assertIn("Formato", err)
        for arguments in (("list", "--allow-extension"), ("list", "--limit", "0"),
                          ("verify", "--checkpoint", "00")):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                self.run_cli(*arguments)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_key_with_open_permissions_is_rejected(self):
        _, token, _ = self.run_cli("checkpoint", "--key-file", self.key)
        self.key.chmod(0o644)
        status, _, err = self.run_cli("checkpoint", "--key-file", self.key)
        self.assertEqual(status, 1)
        self.assertIn("chmod 600", err)
        self.key.chmod(0o600)
        self.assertEqual(self.run_cli("verify", "--checkpoint", token.strip(), "--key-file", self.key)[0], 0)

    def test_private_signing_key_with_open_permissions_is_rejected(self):
        openssl = os.environ.get("LEDGER_OPENSSL", "openssl")
        version = subprocess.run([openssl, "version"], capture_output=True, text=True)
        if os.name != "posix" or not version.stdout.startswith("OpenSSL 3."):
            self.skipTest("OpenSSL 3 e permessi POSIX richiesti")
        private = self.root / "ledger.private.der"
        generate(private)
        self.assertEqual(self.run_cli("checkpoint", "--private-key", private)[0], 0)
        private.chmod(0o640)
        status, out, err = self.run_cli("checkpoint", "--private-key", private)
        self.assertEqual((status, out), (1, ""))
        self.assertIn("chmod 600", err)

    def test_non_integer_height_is_an_integrity_error(self):
        with sqlite3.connect(self.root / "ledger.db") as db:
            rows = db.execute("SELECT * FROM blocks").fetchall()
            db.execute("DROP TABLE blocks")
            db.execute("CREATE TABLE blocks (height, created_ns, parent, payload, digest)")
            db.executemany("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)",
                           [(float(row[0]), *row[1:]) for row in rows])
        status, out, err = self.run_cli("verify")
        self.assertEqual((status, out, err), (1, "", "Blocco non valido alla posizione 0.\n"))

    def test_json_output(self):
        def run(*args):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = main(["--db", str(self.root / "ledger.db"), "--json", *map(str, args)])
            return status, [json.loads(line) for line in out.getvalue().splitlines()], err.getvalue()

        status, (verified,), _ = run("verify")
        self.assertEqual((status, verified["blocks"]), (0, 2))
        status, blocks, _ = run("list")
        self.assertEqual([block["height"] for block in blocks], [0, 1])
        self.assertEqual(blocks[1]["digest"], verified["tip"])
        self.assertEqual(blocks[0]["kind"], "payload")
        self.assertIsInstance(blocks[0]["created_ns"], int)
        status, (sealed,), _ = run("checkpoint", "--key-file", self.key)
        self.assertEqual((sealed["blocks"], sealed["tip"]), (2, verified["tip"]))
        options = ("--checkpoint", sealed["checkpoint"], "--key-file", self.key)
        self.assertEqual(run("verify", *options)[1], [verified])
        absent = self.write("absent", b"never stored")
        status, found, _ = run("find", self.second, absent)
        self.assertEqual(status, 1)
        self.assertEqual(found, [{"file": self.second, "heights": [1]}, {"file": absent, "heights": []}])
        status, (added,), _ = run("append", absent)
        self.assertEqual(added["height"], 2)
        status, out, err = run("verify", "--tip", verified["tip"])
        self.assertEqual((status, out), (1, []))
        self.assertEqual(list(json.loads(err)), ["error"])
        status, (exported,), _ = run("export", "2", "--output", self.root / "copy")
        self.assertEqual(exported, {"height": 2, "bytes": 12, "output": str(self.root / "copy")})


if __name__ == "__main__":
    unittest.main()
