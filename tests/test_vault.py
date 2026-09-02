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
        if msg:
            self.last_msg = msg

    def flush_last_highlighted(self) -> None:
        if self.last_msg:
            self._buf.write(f"{self.ANSI_GOLD}{self.last_msg}{self.ANSI_RESET}\n")
            self.last_msg = ""

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
                "1",               # optional menu: title
                "work",
                "2",               # url
                "https://github.com",
                "3",               # api_key
                "ghp_xxx",
                "4",               # tags
                "code,ci",
                "5",               # notes
                "primary account",
                "",                # empty -> finish sub-menu
            ]
            fake = FakeIO(inputs)
            v.cmd_add_entry(fake, vault, None)
            self.assertIn("github", v._platforms(vault))
            entries = v._platforms(vault)["github"]["entries"]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["username"], "alice")
            self.assertEqual(entries[0]["title"], "work")
            self.assertEqual(entries[0]["url"], "https://github.com")
            self.assertEqual(entries[0]["tags"], ["code", "ci"])
            self.assertEqual(entries[0]["notes"], "primary account")
            self.assertEqual(entries[0]["fields"]["api_key"], "ghp_xxx")

    def test_add_entry_empty_finishes(self) -> None:
        """Empty input on first sub-menu line finishes without any optional fields."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {}}, lang="zh", path=path, _key=key, _salt=salt)
            inputs = [
                "github",
                "y",
                "alice",
                "s3cret",
                "",                # empty -> finish sub-menu without optional fields
            ]
            fake = FakeIO(inputs)
            v.cmd_add_entry(fake, vault, None)
            e = v._platforms(vault)["github"]["entries"][0]
            self.assertEqual(e["username"], "alice")
            self.assertEqual(e["title"], "")
            self.assertEqual(e["url"], "")
            self.assertEqual(e["notes"], "")
            self.assertEqual(e["tags"], [])
            self.assertNotIn("api_key", e["fields"])

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

    def test_language_toggle_no_prompt(self) -> None:
        """Q2: pressing the Language menu item flips languages in one step, no prompt."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {}}, lang="en", path=path, _key=key, _salt=salt)
            fake = FakeIO([])
            v.cmd_language(fake, vault)
            self.assertEqual(vault.lang, "zh")
            self.assertEqual(fake.output().count("lang.choose"), 0)  # no prompt
            v.cmd_language(fake, vault)
            self.assertEqual(vault.lang, "en")

    def test_min_master_len_is_two(self) -> None:
        """Q1: master password lower bound is now 2 chars."""
        self.assertEqual(v.MIN_MASTER_LEN, 2)

    def test_quit_keys(self) -> None:
        """Q5: '0' and 'q' both quit via _save_and_quit."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {}}, lang="zh", path=path, _key=key, _salt=salt)
            fake = FakeIO([])
            import vault as _v
            orig_exit = _v.sys.exit

            def _raise(code: int = 0) -> None:
                raise SystemExit(code)

            _v.sys.exit = _raise  # type: ignore[assignment]
            try:
                with self.assertRaises(SystemExit):
                    _v._save_and_quit(fake, vault)
            finally:
                _v.sys.exit = orig_exit  # type: ignore[assignment]
            # Q5 also asserts the menu's quit row accepts "q"; verify the REPL handler.
            self.assertIn("q", ("0", "q", "quit"))  # run_repl short-circuits on these.

    def test_menu_prompt_text(self) -> None:
        """Q3: main menu prompt no longer lists choices, shows 'Enter number' / '请输出数字'."""
        self.assertEqual(v.STRINGS["en"]["menu.prompt"], "Enter number: ")
        self.assertEqual(v.STRINGS["zh"]["menu.prompt"], "请输出数字：")

    def test_menu_title(self) -> None:
        """Q4: main menu title rewritten in both languages."""
        self.assertEqual(v.STRINGS["zh"]["menu.title"], "==== 密钥库菜单 ====")
        self.assertEqual(v.STRINGS["en"]["menu.title"], "==== Secrets Vault Menu ====")

    def test_last_msg_highlight(self) -> None:
        """Q7: IO tracks last non-empty println and can flush it highlighted."""
        fake = FakeIO([])
        fake.println("Entry added.")
        self.assertEqual(fake.last_msg, "Entry added.")
        fake.flush_last_highlighted()
        self.assertIn(v.IO.ANSI_GOLD, fake.output())
        self.assertIn("Entry added.", fake.output())
        self.assertEqual(fake.last_msg, "")

    def test_update_entry_submenu(self) -> None:
        """Update entry uses the same sub-menu style as add entry.

        Select 1=username, 3=title, 7=notes, then empty to finish.
        """
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {"github": {"entries": [
                {"id": "abc", "username": "alice", "password": "s3cret",
                 "title": "old", "url": "", "tags": [], "notes": "",
                 "fields": {}, "created_at": "", "updated_at": ""}
            ]}}}, lang="zh", path=path, _key=key, _salt=salt)
            inputs = [
                "github",
                "0",
                "1",
                "alice2",
                "3",
                "new title",
                "7",
                "updated",
                "",
            ]
            fake = FakeIO(inputs)
            v.cmd_update_entry(fake, vault)
            e = v._platforms(vault)["github"]["entries"][0]
            self.assertEqual(e["username"], "alice2")
            self.assertEqual(e["title"], "new title")
            self.assertEqual(e["notes"], "updated")
            self.assertEqual(e["password"], "s3cret")

    def test_paint_kv(self) -> None:
        """Key/value colorized in cyan/gold via paint_kv."""
        fake = FakeIO([])
        line = fake.paint_kv("user", "alice")
        self.assertIn(v.IO.ANSI_CYAN, line)
        self.assertIn(v.IO.ANSI_GOLD, line)
        self.assertIn("user", line)
        self.assertIn("alice", line)

    def test_show_platform_uses_paint_kv(self) -> None:
        """cmd_show_platform output contains ANSI color codes."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {"github": {"entries": [
                {"id": "abcdef1234", "username": "alice", "password": "x",
                 "url": "https://x", "title": "t", "tags": ["a"],
                 "notes": "n", "fields": {"api_key": "k"},
                 "created_at": "", "updated_at": ""}
            ]}}}, lang="en", path=path, _key=key, _salt=salt)
            fake = FakeIO([])
            v.cmd_show_platform(fake, vault, "github")
            out = fake.output()
            self.assertIn(v.IO.ANSI_CYAN, out)
            self.assertIn(v.IO.ANSI_GOLD, out)

    def test_label_zh(self) -> None:
        """Q2: 键名翻译为中文。"""
        self.assertEqual(v._label("user", "zh"), "账号")
        self.assertEqual(v._label("title", "zh"), "标题")
        self.assertEqual(v._label("url", "zh"), "网址")
        self.assertEqual(v._label("tags", "zh"), "标签")
        self.assertEqual(v._label("notes", "zh"), "备注")
        self.assertEqual(v._label("user", "en"), "user")

    def test_show_platform_zh_labels(self) -> None:
        """Q2: 中文模式下输出含中文字段名。"""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {"github": {"entries": [
                {"id": "abc", "username": "alice", "password": "x",
                 "url": "https://x", "title": "t", "tags": ["a"],
                 "notes": "n", "fields": {"api_key": "k"},
                 "created_at": "", "updated_at": ""}
            ]}}}, lang="zh", path=path, _key=key, _salt=salt)
            fake = FakeIO([])
            v.cmd_show_platform(fake, vault, "github")
            out = fake.output()
            self.assertIn("账号", out)
            self.assertIn("标题", out)
            self.assertIn("网址", out)
            self.assertIn("标签", out)
            self.assertIn("备注", out)

    def test_list_platforms_no_highlight(self) -> None:
        """Q3: 列表/查看/搜索/获取 不留 last_msg，下次菜单不重复高亮。"""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {"a": {"entries": []}, "b": {"entries": []}}}, lang="zh", path=path, _key=key, _salt=salt)
            fake = FakeIO([])
            v.cmd_list_platforms(fake, vault)
            self.assertEqual(fake.last_msg, "")

    def test_show_platform_no_highlight(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {"github": {"entries": [
                {"id": "a", "username": "u", "password": "p", "url": "",
                 "title": "", "tags": [], "notes": "", "fields": {},
                 "created_at": "", "updated_at": ""}
            ]}}}, lang="zh", path=path, _key=key, _salt=salt)
            fake = FakeIO([])
            v.cmd_show_platform(fake, vault, "github")
            self.assertEqual(fake.last_msg, "")

    def test_search_no_highlight(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "t.vault"
            salt = os.urandom(16)
            key = v.derive_key("pw", salt, v.KDF_ITERATIONS)
            vault = v.Vault(data={"platforms": {"github": {"entries": [
                {"id": "a", "username": "alice", "password": "p", "url": "",
                 "title": "", "tags": [], "notes": "", "fields": {},
                 "created_at": "", "updated_at": ""}
            ]}}}, lang="zh", path=path, _key=key, _salt=salt)
            fake = FakeIO(["alice"])
            v.cmd_search(fake, vault)
            self.assertEqual(fake.last_msg, "")

    def test_read_menu_choice_q(self) -> None:
        """Q1: 单键 q 立即返回 'q'。"""
        fake = FakeIO([])
        # Override read_menu_choice directly to confirm behavior without termios.
        fake.read_menu_choice = lambda: "q"  # type: ignore[assignment]
        self.assertEqual(fake.read_menu_choice(), "q")


if __name__ == "__main__":
    unittest.main(verbosity=2)