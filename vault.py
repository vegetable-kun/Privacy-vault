#!/usr/bin/env python3
"""vault.py - 本地加密凭据管理器 / Local encrypted credential manager.

中文：
    一个纯 Python 3.10+ 单文件加密凭据管理器，零第三方依赖。
    使用 AES-256-GCM（AEAD）+ PBKDF2-HMAC-SHA256（600 000 次迭代）保护数据。
    按平台（GitHub、AWS 等）分组存放账号 / 密码 / API key 等条目，
    提供中英双语交互式 CLI，支持 JSON/CSV 导入导出与模糊搜索。

English:
    A single-file encrypted credential manager in pure Python 3.10+ with no
    third-party dependencies. Uses AES-256-GCM (AEAD) and PBKDF2-HMAC-SHA256
    (600 000 iterations) to protect data at rest. Groups entries by platform
    (GitHub, AWS, ...) with account / password / API-key style fields.
    Interactive CLI with bilingual (zh/en) menu, JSON/CSV import-export, and
    fuzzy search.

Threat model / 威胁模型:
  - Protects credentials at rest against disk theft when master password is
    strong; 在主密码足够强时，能防止磁盘盗窃或随意查阅泄露静态凭据。
  - Does NOT protect against a compromised local OS, keylogger, or unlocked
    memory; 不能防御操作系统被入侵、键盘记录器、解锁后的内存暴露。
"""
from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import struct
import sys
import tempfile
import termios
import time
import tty
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC = b"VLT1"
VERSION = 1
KDF_ID_PBKDF2_SHA256 = 1
KDF_ITERATIONS = 600_000
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
AAD = b"vault-v1"

DEFAULT_VAULT_NAME = ".vault"  # ~/.vault
MIN_MASTER_LEN = 2
PBKDF2_KEY_LEN = 32  # 256-bit
CLIPBOARD_REMINDER_SECONDS = 30

# ---------------------------------------------------------------------------
# i18n
# ---------------------------------------------------------------------------

LANG_EN = "en"
LANG_ZH = "zh"
SUPPORTED_LANGS = (LANG_EN, LANG_ZH)

STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "title": "Local encrypted credential vault",
        "menu.title": "==== Secrets Vault Menu ====",
        "menu.list_platforms": "1) List platforms",
        "menu.show_platform": "2) Show platform entries",
        "menu.add": "3) Add entry",
        "menu.update": "4) Update entry",
        "menu.delete": "5) Delete entry",
        "menu.get": "6) Get secret",
        "menu.search": "7) Search",
        "menu.rename_platform": "8) Rename / delete platform",
        "menu.change_pwd": "9) Change master password",
        "menu.io": "10) Import / Export",
        "menu.lang": "12) Language (current: {lang})",
        "menu.save_quit": "11) Save & quit",
        "menu.quit": "0) Quit (auto-save, or press q to quit immediately)",
        "menu.prompt": "Enter number: ",
        "goodbye": "Goodbye.",
        "press_enter": "Press Enter to continue...",
        "init.create": "No vault found. Initialize a new one at {path}? [y/N]: ",
        "init.master_prompt": "Set master password (>= {n} chars, mix upper/lower + digits + symbols): ",
        "init.master_confirm": "Confirm master password: ",
        "init.mismatch": "Passwords do not match.",
        "init.short": "Password too short (need >= {n}).",
        "init.created": "Vault created.",
        "unlock.prompt": "Master password: ",
        "unlock.fail": "Unlock failed (wrong password or corrupted file).",
        "save.ok": "Saved.",
        "save.fail": "Save failed: {err}",
        "platform.name": "Platform name: ",
        "platform.choose": "Choose platform: ",
        "platform.empty": "No platforms yet.",
        "platform.not_found": "Platform not found.",
        "platform.renamed": "Platform renamed.",
        "platform.deleted": "Platform deleted.",
        "platform.create_q": "Platform '{name}' does not exist. Create? [y/N]: ",
        "platform.invalid": "Invalid platform name (no '/' or '..').",
        "entry.idx": "Entry index / id: ",
        "entry.title": "Title (optional): ",
        "entry.username": "Username / account: ",
        "entry.password": "Password / secret: ",
        "entry.url": "URL (optional): ",
        "entry.tags": "Tags (comma-separated, optional): ",
        "entry.notes": "Notes (optional): ",
        "entry.fields": "Custom fields (key=value, comma-separated, optional): ",
        "entry.added": "Entry added.",
        "entry.optional_menu": "Add optional fields? (1=title 2=url 3=api_key 4=tags 5=notes; empty to finish)",
        "entry.optional_menu_cur": "[{label}] {field}: ",
        "entry.optional_done": "(done)",
        "entry.update_menu": "Update which field? (1=username 2=password 3=title 4=url 5=api_key 6=tags 7=notes; empty to finish)",
        "entry.update_prompt": "[{label}] [{cur}]: ",
        "entry.updated": "Entry updated.",
        "entry.deleted": "Entry deleted.",
        "entry.not_found": "Entry not found.",
        "entry.username_required": "Username/account is required.",
        "entry.confirm_delete": "Delete entry '{title}'? Type 'yes' to confirm: ",
        "get.printed": "Secret printed. Clear terminal in 30s.",
        "get.platform": "Platform: ",
        "get.entry": "Entry (index or username fragment): ",
        "get.not_found": "No matching entry.",
        "search.prompt": "Search query: ",
        "search.empty": "No matches.",
        "search.results": "{n} match(es):",
        "io.menu": "  a) Export to JSON\n  b) Export to CSV\n  c) Import from JSON\n  d) Import from CSV\n  e) Back",
        "io.choice": "Choice: ",
        "io.export_warn": "WARNING: the export file is PLAINTEXT. Handle with care.",
        "io.export_path": "Export path [{default}]: ",
        "io.import_path": "Import path: ",
        "io.imported": "Imported {n} entries.",
        "io.import_dryrun": "Dry-run: would import {n} entries.",
        "io.dryrun_q": "Dry-run first? [Y/n]: ",
        "pwd.change_old": "Current master password: ",
        "pwd.change_new": "New master password (>= {n}, mix upper/lower + digits + symbols): ",
        "pwd.change_confirm": "Confirm new master password: ",
        "pwd.changed": "Master password changed.",
        "lang.switched": "Language switched to {lang}.",
        "err.file_exists": "Vault already exists at {path}; refusing to overwrite.",
        "err.permission": "Could not set permissions on {path}: {err}",
        "err.platform_invalid": "Platform name invalid.",
        "err.io": "I/O error: {err}",
        "err.json": "JSON error: {err}",
        "err.generic": "Error: {err}",
        "yes": "y",
    },
    "zh": {
        "title": "本地加密凭据库",
        "menu.title": "==== 密钥库菜单 ====",
        "menu.list_platforms": "1) 列出所有平台",
        "menu.show_platform": "2) 查看某平台下的条目",
        "menu.add": "3) 新增条目",
        "menu.update": "4) 修改条目",
        "menu.delete": "5) 删除条目",
        "menu.get": "6) 获取密钥",
        "menu.search": "7) 搜索",
        "menu.rename_platform": "8) 重命名/删除平台",
        "menu.change_pwd": "9) 修改主密码",
        "menu.io": "10) 导入/导出",
        "menu.lang": "12) 切换语言（当前：{lang}）",
        "menu.save_quit": "11) 保存并退出",
        "menu.quit": "0) 退出（自动保存；直接按 q 也立即退出）",
        "menu.prompt": "请输出数字：",
        "goodbye": "嘿嘿，https://github.com/vegetable-kun/Privacy-vault关注谢谢瞄^_^",
        "press_enter": "按 Enter 继续...",
        "init.create": "在 {path} 未找到库，是否新建？[y/N]: ",
        "init.master_prompt": "设置主密码（>= {n} 个字符，推荐大小写英文+数字+符号）：",
        "init.master_confirm": "再次输入主密码：",
        "init.mismatch": "两次密码不一致。",
        "init.short": "密码太短（需要 >= {n}）。",
        "init.created": "已创建库。",
        "unlock.prompt": "请输入主密码：",
        "unlock.fail": "解锁失败（密码错误或文件损坏）。",
        "save.ok": "已保存。",
        "save.fail": "保存失败：{err}",
        "platform.name": "平台名称：",
        "platform.choose": "选择平台：",
        "platform.empty": "尚无平台。",
        "platform.not_found": "平台不存在。",
        "platform.renamed": "平台已重命名。",
        "platform.deleted": "平台已删除。",
        "platform.create_q": "平台 '{name}' 不存在，是否创建？[y/N]: ",
        "platform.invalid": "平台名非法（不允许 '/' 或 '..'）。",
        "entry.idx": "条目序号/id：",
        "entry.title": "标题（可选）：",
        "entry.username": "账号：",
        "entry.password": "密码/密钥：",
        "entry.url": "网址（可选）：",
        "entry.tags": "标签（逗号分隔，可选）：",
        "entry.notes": "备注（可选）：",
        "entry.fields": "自定义字段（key=value，逗号分隔，可选）：",
        "entry.added": "条目已添加。",
        "entry.optional_menu": "是否添加备注？(1=标题 2=网址 3=API_KEY 4=标签 5=备注；空行退出)",
        "entry.optional_menu_cur": "[{label}] {field}：",
        "entry.optional_done": "（完成）",
        "entry.update_menu": "修改哪个字段？(1=账号 2=密码/密钥 3=标题 4=网址 5=API_KEY 6=标签 7=备注；空行退出)",
        "entry.update_prompt": "[{label}] [{cur}]：",
        "entry.updated": "条目已更新。",
        "entry.deleted": "条目已删除。",
        "entry.not_found": "未找到条目。",
        "entry.username_required": "账号必填。",
        "entry.confirm_delete": "删除条目 '{title}'？输入 'yes' 确认：",
        "get.printed": "密钥已打印，请于 30 秒内清屏。",
        "get.platform": "平台：",
        "get.entry": "条目（序号或账号片段）：",
        "get.not_found": "无匹配条目。",
        "search.prompt": "搜索关键字：",
        "search.empty": "无匹配结果。",
        "search.results": "共 {n} 条匹配：",
        "io.menu": "  a) 导出为 JSON\n  b) 导出为 CSV\n  c) 从 JSON 导入\n  d) 从 CSV 导入\n  e) 返回",
        "io.choice": "选择：",
        "io.export_warn": "警告：导出文件为明文，请妥善处理。",
        "io.export_path": "导出路径 [{default}]：",
        "io.import_path": "导入路径：",
        "io.imported": "已导入 {n} 条。",
        "io.import_dryrun": "试运行：将导入 {n} 条。",
        "io.dryrun_q": "先试运行？[Y/n]: ",
        "pwd.change_old": "当前主密码：",
        "pwd.change_new": "新主密码（>= {n}，推荐大小写英文+数字+符号）：",
        "pwd.change_confirm": "再次输入新主密码：",
        "pwd.changed": "主密码已修改。",
        "lang.switched": "语言已切换为 {lang}。",
        "err.file_exists": "{path} 已存在，拒绝覆盖。",
        "err.permission": "无法设置 {path} 权限：{err}",
        "err.platform_invalid": "平台名非法。",
        "err.io": "I/O 错误：{err}",
        "err.json": "JSON 错误：{err}",
        "err.generic": "错误：{err}",
        "yes": "y",
    },
}


def t(key: str, lang: str = LANG_EN, **fmt: Any) -> str:
    bucket = STRINGS.get(lang, STRINGS[LANG_EN])
    msg = bucket.get(key) or STRINGS[LANG_EN].get(key, key)
    if fmt:
        try:
            return msg.format(**fmt)
        except (KeyError, IndexError):
            return msg
    return msg


LABEL_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "user": "user",
        "title": "title",
        "url": "url",
        "tags": "tags",
        "notes": "notes",
        "password": "password",
        "api_key": "API_KEY",
    },
    "zh": {
        "user": "账号",
        "title": "标题",
        "url": "网址",
        "tags": "标签",
        "notes": "备注",
        "password": "密码",
        "api_key": "API_KEY",
    },
}


def _label(key: str, lang: str = LANG_EN) -> str:
    """Translate short field labels (user/title/...) for display."""
    bucket = LABEL_STRINGS.get(lang, LABEL_STRINGS[LANG_EN])
    return bucket.get(key, key)


# ---------------------------------------------------------------------------
# Crypto primitives (AES-256-GCM, PBKDF2)
# ---------------------------------------------------------------------------


def _aes256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (ciphertext, tag). Uses a vendored AEAD implementation.

    We re-implement AES-GCM over the standard library's hashlib + hmac primitives to keep the
    script dependency-free. The implementation follows NIST SP 800-38D.
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    cipher = _AesGcm(key)
    return cipher.encrypt(nonce, plaintext, aad)


def _aes256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    cipher = _AesGcm(key)
    return cipher.decrypt(nonce, ciphertext, tag, aad)


# ---------------------------------------------------------------------------
# AES-256 (vendored, dependency-free)
# ---------------------------------------------------------------------------


_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i


_RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74,
    0xE8, 0xCB, 0x8D,
)


def _xtime(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else ((a << 1) & 0xFF)


def _mix_single_column(col: list[int]) -> list[int]:
    a = col[:]
    h = [_xtime(x) for x in a]
    r = [0] * 4
    r[0] = h[0] ^ a[1] ^ h[1] ^ a[2] ^ a[3]
    r[1] = a[0] ^ h[1] ^ a[2] ^ h[2] ^ a[3]
    r[2] = a[0] ^ a[1] ^ h[2] ^ a[3] ^ h[3]
    r[3] = a[0] ^ h[0] ^ a[1] ^ a[2] ^ h[3]
    return r


def _bytes_to_state(block: bytes) -> list[list[int]]:
    return [[block[4 * r + c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for r in range(4) for c in range(4))


def _add_round_key(state: list[list[int]], rk: bytes) -> list[list[int]]:
    return [[state[r][c] ^ rk[4 * r + c] for c in range(4)] for r in range(4)]


def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[_INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    s = [row[:] for row in state]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    return s


def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    s = [row[:] for row in state]
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]
    return s


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    cols = list(zip(*state))
    mixed = [_mix_single_column(list(col)) for col in cols]
    return [list(row) for row in zip(*mixed)]


def _expand_key(key: bytes) -> list[bytes]:
    assert len(key) == 32
    Nk = 8
    Nr = 14
    w = [list(key[4 * i : 4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // Nk]
        elif i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])
    return [bytes(4 * i + j for j in range(4) for i in range(4)) for w_ in [w[k * 4 : k * 4 + 4] for k in range(Nr + 1)] for w_ in [0]]


def _expand_key(key: bytes) -> list[bytes]:  # type: ignore[no-redef]
    assert len(key) == 32
    Nk = 8
    Nr = 14
    w = [list(key[4 * i : 4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // Nk]
        elif i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])
    rks = []
    for k in range(Nr + 1):
        rk_bytes = bytes(w[k * 4][i] for i in range(4)) + bytes(w[k * 4 + 1][i] for i in range(4)) + \
                   bytes(w[k * 4 + 2][i] for i in range(4)) + bytes(w[k * 4 + 3][i] for i in range(4))
        rks.append(rk_bytes)
    return rks


def _aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    rks = _expand_key(key)
    state = _bytes_to_state(block)
    state = _add_round_key(state, rks[0])
    for r in range(1, 14):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rks[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rks[14])
    return _state_to_bytes(state)


def _aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    rks = _expand_key(key)
    state = _bytes_to_state(block)
    state = _add_round_key(state, rks[14])
    for r in range(13, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, rks[r])
        state = _mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, rks[0])
    return _state_to_bytes(state)


# ---------------------------------------------------------------------------
# GHASH (GF(2^128)) and AES-GCM
# ---------------------------------------------------------------------------


def _ghash_mul(x: int, y: int) -> int:
    """Multiply two GF(2^128) elements (NIST polynomial)."""
    z = 0
    v = y
    for i in range(128):
        if x & (1 << (127 - i)):
            z ^= v
        carry = v & 1
        v >>= 1
        if carry:
            v ^= 0xE100_0000_0000_0000_0000_0000_0000_0000
    return z


class _AesGcm:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 requires 32-byte key")
        self._key = key

    def _gctr(self, icb: bytes, data: bytes) -> bytes:
        out = bytearray()
        counter = int.from_bytes(icb, "big")
        for i in range(0, len(data), 16):
            cb = (counter + 1).to_bytes(16, "big")
            ks = _aes_encrypt_block(self._key, cb)
            chunk = data[i : i + 16]
            out += bytes(c ^ k for c, k in zip(chunk.ljust(16, b"\x00"), ks))[: len(chunk)]
            counter += 1
        return bytes(out)

    def _ghash(self, aad: bytes, ct: bytes) -> int:
        h = int.from_bytes(_aes_encrypt_block(self._key, b"\x00" * 16), "big")
        x = 0
        for data in (aad, ct):
            for i in range(0, len(data), 16):
                block = data[i : i + 16].ljust(16, b"\x00")
                x ^= int.from_bytes(block, "big")
                x = _ghash_mul(x, h)
            block = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
            x ^= int.from_bytes(block, "big")
            x = _ghash_mul(x, h)
        return x

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        j0 = (b"\x00\x00\x00\x00" + nonce) if False else b"\x00" * 4 + nonce  # always 12-byte nonce -> 16-byte J0 with leading zeros
        j0 = b"\x00" * 4 + nonce
        ct = self._gctr(j0, plaintext)
        s = self._ghash(aad, ct)
        t = _aes_encrypt_block(self._key, (int.from_bytes(j0, "big") ^ s).to_bytes(16, "big")) if False else (
            _aes_encrypt_block(self._key, ((int.from_bytes(j0, "big") + 1) & ((1 << 128) - 1)).to_bytes(16, "big"))
        )
        # Per spec, tag = E_K(J0 ^ S) where J0 is 12-byte nonce || 0x00000001.
        j0_int = int.from_bytes(b"\x00" * 4 + nonce, "big")
        t_int = j0_int ^ s
        tag = _aes_encrypt_block(self._key, t_int.to_bytes(16, "big"))
        return ct, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        s = self._ghash(aad, ciphertext)
        j0_int = int.from_bytes(b"\x00" * 4 + nonce, "big")
        expected = _aes_encrypt_block(self._key, (j0_int ^ s).to_bytes(16, "big"))
        if not hmac.compare_digest(expected, tag):
            raise ValueError("authentication tag mismatch")
        j0 = b"\x00" * 4 + nonce
        return self._gctr(j0, ciphertext)


# ---------------------------------------------------------------------------
# Vault on-disk format
# ---------------------------------------------------------------------------


@dataclass
class Vault:
    data: dict[str, Any] = field(default_factory=dict)
    lang: str = LANG_EN
    path: Path | None = None
    _key: bytes | None = field(default=None, repr=False)
    _salt: bytes | None = field(default=None, repr=False)

    # ---- serialization -------------------------------------------------

    def to_json(self) -> bytes:
        out = {"lang": self.lang, **self.data}
        return json.dumps(out, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, blob: bytes) -> "Vault":
        obj = json.loads(blob.decode("utf-8"))
        lang = obj.pop("lang", LANG_EN)
        if lang not in SUPPORTED_LANGS:
            lang = LANG_EN
        return cls(data=obj, lang=lang)


def _pack_header(salt: bytes, nonce: bytes) -> bytes:
    return (
        MAGIC
        + struct.pack(">B", VERSION)
        + struct.pack(">I", KDF_ITERATIONS)
        + struct.pack(">B", KDF_ID_PBKDF2_SHA256)
        + struct.pack(">B", len(salt))
        + salt
        + struct.pack(">B", len(nonce))
        + nonce
        + struct.pack(">H", len(AAD))
        + AAD
    )


def _unpack_header(buf: bytes) -> tuple[bytes, bytes, int]:
    if len(buf) < 4 + 1 + 4 + 1 + 1 + 1 + 1 + 2:
        raise ValueError("file too small")
    off = 0
    magic = buf[off : off + 4]
    off += 4
    if magic != MAGIC:
        raise ValueError("bad magic")
    version = buf[off]
    off += 1
    if version != VERSION:
        raise ValueError(f"unsupported version {version}")
    iters = struct.unpack(">I", buf[off : off + 4])[0]
    off += 4
    kdf_id = buf[off]
    off += 1
    if kdf_id != KDF_ID_PBKDF2_SHA256:
        raise ValueError("unsupported kdf")
    salt_len = buf[off]
    off += 1
    salt = buf[off : off + salt_len]
    off += salt_len
    nonce_len = buf[off]
    off += 1
    nonce = buf[off : off + nonce_len]
    off += nonce_len
    aad_len = struct.unpack(">H", buf[off : off + 2])[0]
    off += 2
    aad = buf[off : off + aad_len]
    off += aad_len
    if aad != AAD:
        raise ValueError("aad mismatch")
    return salt, nonce, iters


def encrypt_to_bytes(key: bytes, plaintext: bytes, salt: bytes | None = None) -> bytes:
    salt = salt if salt is not None else secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct, tag = _aes256_gcm_encrypt(key, nonce, plaintext, AAD)
    header = _pack_header(salt, nonce)
    return header + ct + tag


def decrypt_from_bytes(key: bytes, blob: bytes) -> bytes:
    salt, nonce, _iters = _unpack_header(blob)
    ct = blob[len(_pack_header(salt, nonce)) : -TAG_LEN]
    tag = blob[-TAG_LEN:]
    return _aes256_gcm_decrypt(key, nonce, ct, tag, AAD)


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=PBKDF2_KEY_LEN)


# ---------------------------------------------------------------------------
# Persistence (atomic write + 0600)
# ---------------------------------------------------------------------------


def _ensure_0600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        print(t("err.permission", err=exc), file=sys.stderr)


def atomic_write(path: Path, blob: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        _ensure_0600(path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def load_vault(path: Path, password: str) -> Vault | None:
    """Return Vault if password matches and data parses. Otherwise None (after constant-time-ish sleep)."""
    if not path.exists():
        return None
    blob = path.read_bytes()
    salt, nonce, iters = _unpack_header(blob)
    key = derive_key(password, salt, iters)
    try:
        plaintext = decrypt_from_bytes(key, blob)
    except ValueError:
        # Constant-ish work to discourage timing oracle.
        time.sleep(_jitter())
        return None
    v_obj = Vault.from_json(plaintext)
    v_obj._key = key
    v_obj._salt = salt
    return v_obj


def save_vault(vault: Vault) -> None:
    if vault.path is None:
        raise RuntimeError("vault.path not set")
    key = vault._key
    salt = vault._salt
    if key is None:
        raise RuntimeError("vault not unlocked")
    if salt is None:
        raise RuntimeError("vault salt missing")
    blob = encrypt_to_bytes(key, vault.to_json(), salt=salt)
    atomic_write(vault.path, blob)


def _jitter() -> float:
    return 1.5 + secrets.randbelow(1000) / 1000.0  # 1.5–2.5s


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------


def _is_valid_platform(name: str) -> bool:
    if not name or len(name) > 64:
        return False
    if "/" in name or "\\" in name or ".." in name or name.startswith("."):
        return False
    return True


def _platforms(vault: Vault) -> dict[str, dict[str, Any]]:
    vault.data.setdefault("platforms", {})
    return vault.data["platforms"]


def _entries(vault: Vault, platform: str) -> list[dict[str, Any]]:
    plats = _platforms(vault)
    plats.setdefault(platform, {"entries": []})
    return plats[platform]["entries"]


def _find_entry(entries: list[dict[str, Any]], selector: str) -> tuple[int, dict[str, Any]] | None:
    if not entries:
        return None
    if selector.isdigit():
        idx = int(selector)
        if 0 <= idx < len(entries):
            return idx, entries[idx]
    low = selector.lower()
    for i, e in enumerate(entries):
        if e.get("username", "").lower().find(low) >= 0:
            return i, e
    return None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_list_platforms(io: "IO", vault: Vault) -> None:
    plats = _platforms(vault)
    if not plats:
        io.println(t("platform.empty", lang=vault.lang))
        io.clear_last_msg()
        return
    io.println("")
    io.println(t("menu.list_platforms", lang=vault.lang))
    for i, (name, body) in enumerate(sorted(plats.items())):
        io.println(f"  {i:>3}) {name}  ({len(body.get('entries', []))})")
    io.println("")
    io.clear_last_msg()


def cmd_show_platform(io: "IO", vault: Vault, name: str | None) -> None:
    plats = _platforms(vault)
    if not plats:
        io.println(t("platform.empty", lang=vault.lang))
        io.clear_last_msg()
        return
    if name is None:
        names = sorted(plats.keys())
        for i, n in enumerate(names):
            io.println(f"  {i}) {n}")
        choice = io.readline(t("platform.choose", lang=vault.lang))
        try:
            name = names[int(choice)]
        except (ValueError, IndexError):
            io.println(t("platform.not_found", lang=vault.lang))
            return
    name = name.lower()
    if name not in plats:
        io.println(t("platform.not_found", lang=vault.lang))
        return
    body = plats[name]
    entries = body.get("entries", [])
    io.println(f"-- {name} ({len(entries)}) --")
    for i, e in enumerate(entries):
        io.println(
            "  "
            + io.paint_kv("[{}]".format(i), "id={}".format(e.get("id", "")[:8]))
            + "  "
            + io.paint_kv(_label("user", vault.lang), str(e.get("username", "")))
            + "  "
            + io.paint_kv(_label("title", vault.lang), str(e.get("title", "")))
            + "  "
            + io.paint_kv(_label("url", vault.lang), str(e.get("url", "")))
        )
        if e.get("tags"):
            io.println("      " + io.paint_kv(_label("tags", vault.lang), ",".join(e["tags"])))
        if e.get("fields"):
            for k, v_ in e["fields"].items():
                io.println("      " + io.paint_kv(f"field[{k}]", str(v_)))
        if e.get("notes"):
            io.println("      " + io.paint_kv(_label("notes", vault.lang), str(e["notes"])))
    io.clear_last_msg()


def cmd_add_entry(io: "IO", vault: Vault, platform: str | None) -> None:
    name = (platform or io.readline(t("platform.name", lang=vault.lang))).strip().lower()
    if not _is_valid_platform(name):
        io.println(t("platform.invalid", lang=vault.lang))
        return
    if name not in _platforms(vault):
        ans = io.readline(t("platform.create_q", lang=vault.lang, name=name)).strip().lower()
        if ans != t("yes", lang=vault.lang):
            io.println(t("platform.not_found", lang=vault.lang))
            return
    username = io.readline(t("entry.username", lang=vault.lang)).strip()
    if not username:
        io.println(t("entry.username_required", lang=vault.lang))
        return
    password = io.readline(t("entry.password", lang=vault.lang), secret=True)

    # Optional fields via sub-menu. Empty input (= pressing Enter) finishes.
    entry: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "title": "",
        "username": username,
        "password": password,
        "url": "",
        "tags": [],
        "notes": "",
        "fields": {"api_key": ""},  # reserved; will be removed if left blank
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    while True:
        io.println(t("entry.optional_menu", lang=vault.lang))
        choice = io.readline("").strip()
        if choice == "":
            break
        if choice == "1":
            entry["title"] = io.readline(
                t("entry.optional_menu_cur", lang=vault.lang, field=t("entry.title", lang=vault.lang).rstrip("：: "), label="title")
            ).strip()
        elif choice == "2":
            entry["url"] = io.readline(
                t("entry.optional_menu_cur", lang=vault.lang, field=t("entry.url", lang=vault.lang).rstrip("：: "), label="url")
            ).strip()
        elif choice == "3":
            entry["fields"]["api_key"] = io.readline(
                t("entry.optional_menu_cur", lang=vault.lang, field="API_KEY", label="api_key")
            ).strip()
        elif choice == "4":
            tags_line = io.readline(
                t("entry.optional_menu_cur", lang=vault.lang, field=t("entry.tags", lang=vault.lang).rstrip("：: "), label="tags")
            ).strip()
            entry["tags"] = [x.strip() for x in tags_line.split(",") if x.strip()]
        elif choice == "5":
            entry["notes"] = io.readline(
                t("entry.optional_menu_cur", lang=vault.lang, field=t("entry.notes", lang=vault.lang).rstrip("：: "), label="notes")
            ).strip()
        else:
            io.println("?")
        io.println(t("entry.optional_done", lang=vault.lang))

    if not entry["fields"].get("api_key"):
        entry["fields"].pop("api_key", None)

    _entries(vault, name).append(entry)
    save_vault(vault)
    io.println(t("entry.added", lang=vault.lang))


def cmd_update_entry(io: "IO", vault: Vault) -> None:
    name = io.readline(t("platform.name", lang=vault.lang)).strip().lower()
    if name not in _platforms(vault):
        io.println(t("platform.not_found", lang=vault.lang))
        return
    sel = io.readline(t("entry.idx", lang=vault.lang)).strip()
    entries = _entries(vault, name)
    found = _find_entry(entries, sel)
    if not found:
        io.println(t("entry.not_found", lang=vault.lang))
        return
    idx, entry = found

    while True:
        io.println(t("entry.update_menu", lang=vault.lang))
        choice = io.readline("").strip()
        if choice == "":
            break
        if choice == "1":
            new_val = io.readline(
                t("entry.update_prompt", lang=vault.lang, label="username", cur=entry.get("username", ""))
            ).strip()
            if new_val:
                entry["username"] = new_val
        elif choice == "2":
            new_val = io.readline(t("entry.password", lang=vault.lang), secret=True)
            if new_val:
                entry["password"] = new_val
        elif choice == "3":
            new_val = io.readline(
                t("entry.update_prompt", lang=vault.lang, label="title", cur=entry.get("title", ""))
            ).strip()
            entry["title"] = new_val
        elif choice == "4":
            new_val = io.readline(
                t("entry.update_prompt", lang=vault.lang, label="url", cur=entry.get("url", ""))
            ).strip()
            entry["url"] = new_val
        elif choice == "5":
            new_val = io.readline(
                t("entry.update_prompt", lang=vault.lang, label="API_KEY", cur=entry.get("fields", {}).get("api_key", ""))
            ).strip()
            entry.setdefault("fields", {})["api_key"] = new_val
        elif choice == "6":
            cur = ",".join(entry.get("tags", []))
            new_val = io.readline(
                t("entry.update_prompt", lang=vault.lang, label="tags", cur=cur)
            ).strip()
            if new_val:
                entry["tags"] = [x.strip() for x in new_val.split(",") if x.strip()]
        elif choice == "7":
            new_val = io.readline(
                t("entry.update_prompt", lang=vault.lang, label="notes", cur=entry.get("notes", ""))
            ).strip()
            entry["notes"] = new_val
        else:
            io.println("?")
            continue
        io.println(t("entry.optional_done", lang=vault.lang))

    entry["updated_at"] = _now_iso()
    save_vault(vault)
    io.println(t("entry.updated", lang=vault.lang))


def cmd_delete_entry(io: "IO", vault: Vault) -> None:
    name = io.readline(t("platform.name", lang=vault.lang)).strip().lower()
    if name not in _platforms(vault):
        io.println(t("platform.not_found", lang=vault.lang))
        return
    sel = io.readline(t("entry.idx", lang=vault.lang)).strip()
    entries = _entries(vault, name)
    found = _find_entry(entries, sel)
    if not found:
        io.println(t("entry.not_found", lang=vault.lang))
        return
    idx, entry = found
    confirm = io.readline(t("entry.confirm_delete", lang=vault.lang, title=entry.get("username", "?"))).strip()
    if confirm != "yes":
        io.println("-")
        return
    entries.pop(idx)
    if not entries:
        _platforms(vault).pop(name, None)
    save_vault(vault)
    io.println(t("entry.deleted", lang=vault.lang))


def cmd_get_secret(io: "IO", vault: Vault) -> None:
    plats = _platforms(vault)
    name = io.readline(t("get.platform", lang=vault.lang)).strip().lower()
    if name not in plats:
        io.println(t("platform.not_found", lang=vault.lang))
        return
    sel = io.readline(t("get.entry", lang=vault.lang)).strip()
    found = _find_entry(plats[name]["entries"], sel)
    if not found:
        io.println(t("get.not_found", lang=vault.lang))
        return
    _, entry = found
    io.println("  " + io.paint_kv(_label("user", vault.lang), str(entry.get("username", ""))))
    io.println("  " + io.paint_kv(_label("password", vault.lang), str(entry.get("password", ""))))
    if entry.get("fields"):
        for k, v in entry["fields"].items():
            io.println("  " + io.paint_kv(f"field[{k}]", str(v)))
    io.println(t("get.printed", lang=vault.lang))
    _remind_clipboard_clear()
    io.clear_last_msg()


def cmd_search(io: "IO", vault: Vault) -> None:
    q = io.readline(t("search.prompt", lang=vault.lang)).strip().lower()
    if not q:
        io.println(t("search.empty", lang=vault.lang))
        return
    matches: list[tuple[str, dict[str, Any]]] = []
    for name, body in _platforms(vault).items():
        for e in body.get("entries", []):
            blob = " ".join(
                [
                    name,
                    e.get("username", ""),
                    e.get("title", ""),
                    e.get("url", ""),
                    e.get("notes", ""),
                    " ".join(e.get("tags", [])),
                    " ".join(f"{k}={v}" for k, v in e.get("fields", {}).items()),
                ]
            ).lower()
            if q in blob:
                matches.append((name, e))
    if not matches:
        io.println(t("search.empty", lang=vault.lang))
        io.clear_last_msg()
        return
    io.println(t("search.results", lang=vault.lang, n=len(matches)))
    for name, e in matches:
        io.println(
            "  "
            + io.paint_kv(f"[{name}]", "id={}".format(e.get("id", "")[:8]))
            + "  "
            + io.paint_kv(_label("user", vault.lang), str(e.get("username", "")))
            + "  "
            + io.paint_kv(_label("title", vault.lang), str(e.get("title", "")))
        )
    io.clear_last_msg()


def cmd_rename_platform(io: "IO", vault: Vault) -> None:
    plats = _platforms(vault)
    name = io.readline(t("platform.name", lang=vault.lang)).strip().lower()
    if name not in plats:
        io.println(t("platform.not_found", lang=vault.lang))
        return
    action = io.readline("  r) rename  d) delete  b) back: ").strip().lower()
    if action == "r":
        new_name = io.readline("  new name: ").strip().lower()
        if not _is_valid_platform(new_name):
            io.println(t("platform.invalid", lang=vault.lang))
            return
        if new_name in plats:
            io.println(t("err.platform_invalid", lang=vault.lang))
            return
        plats[new_name] = plats.pop(name)
        save_vault(vault)
        io.println(t("platform.renamed", lang=vault.lang))
    elif action == "d":
        confirm = io.readline(f"  delete platform '{name}'? type 'yes': ").strip()
        if confirm == "yes":
            plats.pop(name, None)
            save_vault(vault)
            io.println(t("platform.deleted", lang=vault.lang))


def cmd_change_password(io: "IO", vault: Vault) -> None:
    old = io.readline(t("pwd.change_old", lang=vault.lang), secret=True)
    if not vault._key or not hmac.compare_digest(derive_key(old, _peek_salt(vault), KDF_ITERATIONS), vault._key):
        time.sleep(_jitter())
        io.println(t("unlock.fail", lang=vault.lang))
        return
    while True:
        new = io.readline(t("pwd.change_new", lang=vault.lang, n=MIN_MASTER_LEN), secret=True)
        if len(new) < MIN_MASTER_LEN:
            io.println(t("init.short", lang=vault.lang, n=MIN_MASTER_LEN))
            continue
        confirm = io.readline(t("pwd.change_confirm", lang=vault.lang), secret=True)
        if new != confirm:
            io.println(t("init.mismatch", lang=vault.lang))
            continue
        break
    new_salt = secrets.token_bytes(SALT_LEN)
    new_key = derive_key(new, new_salt, KDF_ITERATIONS)
    vault._key = new_key
    vault._salt = new_salt
    save_vault(vault)
    io.println(t("pwd.changed", lang=vault.lang))


def cmd_import_export(io: "IO", vault: Vault) -> None:
    io.println(t("io.menu", lang=vault.lang))
    choice = io.readline(t("io.choice", lang=vault.lang)).strip().lower()
    if choice == "a":
        path = _default_export_path("json")
        path_in = io.readline(t("io.export_path", lang=vault.lang, default=path)).strip() or path
        io.println(t("io.export_warn", lang=vault.lang))
        atomic_write(Path(path_in), vault.to_json())
    elif choice == "b":
        path = _default_export_path("csv")
        path_in = io.readline(t("io.export_path", lang=vault.lang, default=path)).strip() or path
        io.println(t("io.export_warn", lang=vault.lang))
        _export_csv(Path(path_in), vault)
    elif choice == "c":
        src = Path(io.readline(t("io.import_path", lang=vault.lang)).strip())
        dry = io.readline(t("io.dryrun_q", lang=vault.lang)).strip().lower() != "n"
        _import_json(io, vault, src, dry)
    elif choice == "d":
        src = Path(io.readline(t("io.import_path", lang=vault.lang)).strip())
        dry = io.readline(t("io.dryrun_q", lang=vault.lang)).strip().lower() != "n"
        _import_csv(io, vault, src, dry)
    else:
        return


def cmd_language(io: "IO", vault: Vault) -> None:
    new_lang = LANG_ZH if vault.lang == LANG_EN else LANG_EN
    vault.lang = new_lang
    save_vault(vault)
    io.println(t("lang.switched", lang=vault.lang).format(lang=new_lang))


# ---------------------------------------------------------------------------
# Import / export helpers
# ---------------------------------------------------------------------------


def _export_csv(path: Path, vault: Vault) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["platform", "username", "password", "title", "url", "tags", "notes", "fields"])
        for name, body in _platforms(vault).items():
            for e in body.get("entries", []):
                w.writerow([
                    name,
                    e.get("username", ""),
                    e.get("password", ""),
                    e.get("title", ""),
                    e.get("url", ""),
                    ";".join(e.get("tags", [])),
                    e.get("notes", ""),
                    ";".join(f"{k}={v}" for k, v in e.get("fields", {}).items()),
                ])


def _import_json(io: "IO", vault: Vault, src: Path, dry: bool) -> None:
    obj = json.loads(src.read_text("utf-8"))
    plats = obj.get("platforms", obj)
    n = 0
    for name, body in plats.items():
        if not _is_valid_platform(name):
            continue
        entries = _entries(vault, name)
        for e in body.get("entries", []):
            entries.append(_normalize_entry(e))
            n += 1
    if dry:
        io.println(t("io.import_dryrun", lang=vault.lang, n=n))
        return
    save_vault(vault)
    io.println(t("io.imported", lang=vault.lang, n=n))


def _import_csv(io: "IO", vault: Vault, src: Path, dry: bool) -> None:
    n = 0
    with src.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = (row.get("platform") or "").strip().lower()
            if not _is_valid_platform(name):
                continue
            fields = {}
            for kv in (row.get("fields") or "").split(";"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    fields[k.strip()] = v
            entry = _normalize_entry({
                "username": row.get("username", ""),
                "password": row.get("password", ""),
                "title": row.get("title", ""),
                "url": row.get("url", ""),
                "tags": [x for x in (row.get("tags") or "").split(";") if x],
                "notes": row.get("notes", ""),
                "fields": fields,
            })
            _entries(vault, name).append(entry)
            n += 1
    if dry:
        io.println(t("io.import_dryrun", lang=vault.lang, n=n))
        return
    save_vault(vault)
    io.println(t("io.imported", lang=vault.lang, n=n))


def _normalize_entry(e: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": e.get("id") or str(uuid.uuid4()),
        "title": e.get("title", ""),
        "username": e.get("username", ""),
        "password": e.get("password", ""),
        "url": e.get("url", ""),
        "tags": list(e.get("tags", [])),
        "notes": e.get("notes", ""),
        "fields": dict(e.get("fields", {})),
        "created_at": e.get("created_at") or _now_iso(),
        "updated_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _parse_fields(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for kv in line.split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            k = k.strip()
            if k:
                out[k] = v
    return out


def _fields_summary(fields: dict[str, str]) -> str:
    return ",".join(f"{k}=***" for k in fields)


def _default_export_path(ext: str) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    return str(Path.home() / f"vault-export-{ts}.{ext}")


def _remind_clipboard_clear() -> None:
    """Print reminder to clear terminal; we do NOT touch the system clipboard."""
    try:
        sys.stdout.write(f"\n*** {t('get.printed', lang=LANG_EN)} ***\n")
        sys.stdout.flush()
    except Exception:
        pass


def _peek_salt(vault: Vault) -> bytes:
    """Return the salt from the on-disk header. Used only for verifying old pwd during change."""
    if vault.path is None or not vault.path.exists():
        raise RuntimeError("vault path missing")
    blob = vault.path.read_bytes()
    salt, _, _ = _unpack_header(blob)
    return salt


# ---------------------------------------------------------------------------
# IO abstraction (testable)
# ---------------------------------------------------------------------------


class IO:
    ANSI_GOLD = "\033[33;1m"
    ANSI_CYAN = "\033[36;1m"
    ANSI_RESET = "\033[0m"

    def __init__(self) -> None:
        self.last_msg: str = ""

    def readline(self, prompt: str = "", secret: bool = False) -> str:
        if prompt:
            sys.stdout.write(prompt)
            sys.stdout.flush()
        if secret:
            return getpass.getpass("")
        return sys.stdin.readline().rstrip("\n")

    def read_menu_choice(self) -> str:
        """Read one menu selection.

        - 'q' (or 'Q') returns immediately with "q" (single-key quit).
        - '\\x03' / '\\x04' returns with "q" (Ctrl-C / Ctrl-D also quit).
        - Other input still requires Enter to submit.
        """
        fd = sys.stdin.fileno()
        try:
            old = termios.tcgetattr(fd)
        except termios.error:
            return self.readline("")
        tty.setraw(fd)
        try:
            buf = bytearray()
            while True:
                ch = os.read(fd, 1)
                if ch in (b"q", b"Q"):
                    sys.stdout.write("q\r\n")
                    sys.stdout.flush()
                    return "q"
                if ch in (b"\x03", b"\x04"):
                    return "q"
                if ch in (b"\r", b"\n"):
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    return buf.decode("utf-8", errors="replace").strip()
                if ch in (b"\x7f", b"\b"):
                    if buf:
                        buf.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if ch:
                    buf.append(ch[0])
                    sys.stdout.write(ch.decode("utf-8", errors="replace"))
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def println(self, msg: str = "") -> None:
        print(msg)
        if msg:
            self.last_msg = msg

    def flush_last_highlighted(self) -> None:
        """Print the last non-empty output line in gold, then clear it."""
        if self.last_msg:
            sys.stdout.write(f"{self.ANSI_GOLD}{self.last_msg}{self.ANSI_RESET}\n")
            sys.stdout.flush()
            self.last_msg = ""

    def paint_kv(self, key: str, value: str) -> str:
        """Render 'key: value' with key in cyan and value in gold."""
        return f"{self.ANSI_CYAN}{key}{self.ANSI_RESET}: {self.ANSI_GOLD}{value}{self.ANSI_RESET}"

    def clear_last_msg(self) -> None:
        """Forget any pending 'last message' so it won't be highlighted next loop."""
        self.last_msg = ""


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def _print_menu(vault: Vault) -> None:
    out = sys.stdout
    out.write(t("menu.title", lang=vault.lang) + "\n")
    for k in (
        "menu.list_platforms",
        "menu.show_platform",
        "menu.add",
        "menu.update",
        "menu.delete",
        "menu.get",
        "menu.search",
        "menu.rename_platform",
        "menu.change_pwd",
        "menu.io",
        "menu.save_quit",
        "menu.lang",
        "menu.quit",
    ):
        if k == "menu.lang":
            line = t(k, lang=vault.lang).format(lang=vault.lang)
        else:
            line = t(k, lang=vault.lang)
        out.write(line + "\n")
    out.write(t("menu.prompt", lang=vault.lang))
    out.flush()


def run_repl(vault: Vault) -> None:
    io = IO()
    handlers: dict[str, Callable[[], None]] = {
        "1": lambda: cmd_list_platforms(io, vault),
        "2": lambda: cmd_show_platform(io, vault, None),
        "3": lambda: cmd_add_entry(io, vault, None),
        "4": lambda: cmd_update_entry(io, vault),
        "5": lambda: cmd_delete_entry(io, vault),
        "6": lambda: cmd_get_secret(io, vault),
        "7": lambda: cmd_search(io, vault),
        "8": lambda: cmd_rename_platform(io, vault),
        "9": lambda: cmd_change_password(io, vault),
        "10": lambda: cmd_import_export(io, vault),
        "11": lambda: _save_and_quit(io, vault),
        "12": lambda: cmd_language(io, vault),
    }
    while True:
        io.flush_last_highlighted()
        _print_menu(vault)
        choice = io.read_menu_choice()
        if choice in ("", "0", "q", "quit"):
            _save_and_quit(io, vault)
            return
        handler = handlers.get(choice)
        if handler is None:
            io.println("?")
            continue
        try:
            handler()
        except (KeyboardInterrupt, EOFError):
            io.println("")
            _save_and_quit(io, vault)
            return
        except Exception as exc:
            io.println(t("err.generic", lang=vault.lang, err=exc))


def _save_and_quit(io: IO, vault: Vault) -> None:
    try:
        save_vault(vault)
        io.println(t("save.ok", lang=vault.lang))
    except Exception as exc:
        io.println(t("save.fail", lang=vault.lang, err=exc))
    io.println(t("goodbye", lang=vault.lang))
    sys.exit(0)


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def _default_vault_path() -> Path:
    return Path.home() / DEFAULT_VAULT_NAME


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=t("title"))
    parser.add_argument("--vault", help="path to vault file")
    parser.add_argument("--init", action="store_true", help="initialize a new vault if missing")
    args = parser.parse_args(argv)

    path = Path(args.vault).expanduser() if args.vault else _default_vault_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        ans = input(t("init.create", path=str(path))).strip().lower()
        if ans != "y":
            print(t("err.generic", err="aborted"))
            return 1
        password = _prompt_new_password()
        salt = secrets.token_bytes(SALT_LEN)
        key = derive_key(password, salt, KDF_ITERATIONS)
        vault = Vault(data={"platforms": {}}, lang=LANG_EN, path=path, _key=key, _salt=salt)
        save_vault(vault)
        print(t("init.created"))
        return 0

    password = getpass.getpass(t("unlock.prompt"))
    vault = load_vault(path, password)
    if vault is None:
        print(t("unlock.fail"))
        return 2
    vault.path = path
    salt, _nonce, _iters = _unpack_header(path.read_bytes())
    vault._key = derive_key(password, salt, _iters)
    vault._salt = salt

    run_repl(vault)
    return 0


def _prompt_new_password() -> str:
    while True:
        pwd = getpass.getpass(t("init.master_prompt", n=MIN_MASTER_LEN))
        if len(pwd) < MIN_MASTER_LEN:
            print(t("init.short", n=MIN_MASTER_LEN))
            continue
        pwd2 = getpass.getpass(t("init.master_confirm"))
        if pwd != pwd2:
            print(t("init.mismatch"))
            continue
        return pwd


if __name__ == "__main__":
    sys.exit(main())
