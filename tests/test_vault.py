"""Stand-alone self-tests for vault.py.

These tests import vault.py as a module so they exercise the real crypto and
JSON helpers (AES-256-GCM round-trip, GCM tag rejection, PBKDF2 derivation,
JSON envelope). They also drive the REPL via a fake IO to validate menu wiring.
Run with: python tests/test_vault.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import vault as v  # noqa: E402


class FakeIO(v.IO):
    def __init__(self, inputs: list[str]) -> None:
        super().__init__()
        self._inputs = list(inputs)
        self._buf = io.StringIO()

    def readline(self, prompt: str = "", secret: bool = False) -> str:  # type: ignore[override]
        if prompt:
            self._buf.write(prompt)
        if not self._inputs:
            return ""
        val = self._inputs.pop(0)
        self._buf.write("*\n" if secret else val + "\n")
        return val

    def println(self, msg: str = "") -> None:
        self._buf.write(msg + "\n")

    def output(self) -> str:
        return self._buf.getvalue()


class CryptoTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        key = b"\x00" * 32
        nonce = b"\x01" * 12
        ct, tag = v._aes256_gcm_encrypt(key, nonce, b"hello world", v.AAD)
        pt = v._aes256_gcm_decrypt(key, nonce, ct, tag, v.AAD)
        self.assertEqual(pt, b"hello world")

    def test_tamper_ciphertext(self) -> None:
        key = b"\x11" * 32
        nonce = b"\x02" * 12
        ct, tag = v._aes256_gcm_encrypt(key, nonce, b"secret payload", v.AAD)
        ct2 = bytes(c ^ 0x01 for c in ct)
        with self.assertRaises(ValueError):
            v._aes256_gcm_decrypt(key, nonce, ct2, tag, v.AAD)

    def test_tamper_tag(self) -> None:
        key = b"\x22" * 32
        nonce = b"\x03" * 12
        ct, tag = v._aes256_gcm_encrypt(key, nonce, b"another secret", v.AAD)
        bad_tag = bytes(b ^ 0xFF for b in tag)
        with self.assertRaises(ValueError):
            v._aes256_gcm_decrypt(key, nonce, ct, bad_tag, v.AAD)

    def test_random_nonces(self) -> None:
        # Two encryptions of the same plaintext under the same key must yield
        # different ciphertext because the nonce is randomized.
        key = b"\x33" * 32
        pt = b"same plaintext"
        a = v.encrypt_to_bytes(key, pt)
        b = v.encrypt_to_bytes(key, pt)
        self.assertNotEqual(a, b)

    def test_kdf_stability(self) -> None:
        salt = b"\x00" * 16
        self.assertEqual(
            v.derive_key("hunter2", salt, 1000),
            v.derive_key("hunter2", salt, 1000),
        )


class FileFormatTests(unittest.TestCase):
    def test_pack_unpack_header(self) -> None:
        salt = b"\xAA" * 16
        nonce = b"\xBB" * 12
        header = v._pack_header(salt, nonce)
        out_salt, out_nonce, iters = v._unpack_header(header)
        self.assertEqual(salt, out_salt)
        self.assertEqual(nonce, out_nonce)
        self.assertEqual(iters, v.KDF_ITERATIONS)


class EndToEndTests(unittest.TestCase):
    def test_init_unlock_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            password = "correct horse battery staple"
            # Persist with a known salt so we can derive the same key on reload.
            salt = os.urandom(16)
            key = v.derive_key(password, salt, v.KDF_ITERATIONS)
            blob = v.encrypt_to_bytes(key, json.dumps({"lang": "en", "platforms": {}}).encode(), salt=salt)
            v.atomic_write(path, blob)
            loaded = v.load_vault(path, password)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.lang, "en")
            self.assertIn("platforms", loaded.data)

    def test_wrong_password(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("right", salt, v.KDF_ITERATIONS)
            blob = v.encrypt_to_bytes(key, json.dumps({"lang": "en", "platforms": {}}).encode(), salt=salt)
            v.atomic_write(path, blob)
            wrong = v.load_vault(path, "wrong")
            self.assertIsNone(wrong)


class ReplTests(unittest.TestCase):
    def test_add_then_get_flow(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {}}, lang="zh", path=path, _key=key, _salt=salt)
            inputs = [
                "github",          # platform
                "y",               # create
                "alice",           # username
                "s3cret",          # password
                "work",            # title
                "https://github.com",
                "code,ci",
                "primary account",
                "api_key=ghp_xxx",  # fields
            ]
            fake = FakeIO(inputs)
            v.cmd_add_entry(fake, vault, None)
            self.assertIn("github", v._platforms(vault))
            entries = v._platforms(vault)["github"]["entries"]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["username"], "alice")
            self.assertEqual(entries[0]["fields"]["api_key"], "ghp_xxx")

    def test_language_persists(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            blob = v.encrypt_to_bytes(key, json.dumps({"lang": "en", "platforms": {}}).encode(), salt=salt)
            v.atomic_write(path, blob)

            loaded = v.load_vault(path, "pw")
            self.assertIsNotNone(loaded)
            loaded.path = path
            loaded.lang = "zh"
            v.save_vault(loaded)

            again = v.load_vault(path, "pw")
            self.assertIsNotNone(again)
            self.assertEqual(again.lang, "zh")


if __name__ == "__main__":
    unittest.main(verbosity=2)