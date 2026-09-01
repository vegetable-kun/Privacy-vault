# vault

A single-file encrypted credential manager written in pure Python 3.10+.
No third-party dependencies — uses only the standard library.

## What it does

- Stores accounts, passwords, API keys, tokens, custom fields per platform
  (e.g. GitHub, AWS, …).
- One platform can hold many entries; each entry has `username`, `password`,
  `url`, `tags`, `notes`, and a free-form `fields` key/value bag for API keys
  or any extra data.
- Master-password-protected. File at rest is opaque ciphertext.
- Interactive CLI with bilingual (English / 简体中文) menus; switchable at
  runtime from the menu (`12) Language`).
- Import / export to plaintext JSON or CSV (with a warning).
- Search across platforms, usernames, URLs, tags, notes, and field values.

## Threat model

Protects credentials at rest against disk theft or casual file inspection,
**assuming**:

- The master password is strong (≥ 12 chars; longer is better).
- The local OS is not compromised at unlock time (no keylogger, no malicious
  process reading memory).

Does **not** protect against a compromised OS, shoulder-surfing, or unlocked
in-memory exposure.

## Crypto

| Component   | Choice                                                    |
| ----------- | --------------------------------------------------------- |
| Cipher      | AES-256-GCM (AEAD; tag checks both integrity + auth)      |
| KDF         | PBKDF2-HMAC-SHA256, 600 000 iterations                    |
| Salt        | 16 bytes, random, generated once at vault creation        |
| Nonce       | 12 bytes, random per write                                |
| AAD         | bound to file format string `vault-v1`                    |

AES-GCM is implemented from scratch in `vault.py` (S-box, MixColumns, GHASH)
to keep the script dependency-free. The implementation follows NIST SP 800-38D.

## Layout

```
vault/
  vault.py             # script entry point (python3 vault.py)
  README.md
  tests/
    test_vault.py      # self-tests (python3 tests/test_vault.py)
```

## Usage

```sh
python3 vault.py            # uses ~/.vault
python3 vault.py --vault /secure/place/my.vault
```

On first run the script prompts to create a new vault and set a master password
(≥ 12 chars, entered twice).

After unlock the menu shows:

```
0) Quit (auto-save)
1) List platforms
2) Show platform entries
3) Add entry
4) Update entry
5) Delete entry
6) Get secret
7) Search
8) Rename / delete platform
9) Change master password
10) Import / Export
11) Save & quit
12) Language (current: en)
```

`6) Get secret` **prints** the secret to the terminal and reminds you to clear
it manually within 30 seconds — it deliberately does **not** touch the system
clipboard.

`9) Change master password` re-encrypts the vault under a new master password
(and rotates the salt).

`10) Import / Export` supports JSON or CSV. Plaintext exports print a clear
warning before writing. Use them for migration / backup and store the output
files with care.

## File format

```
+-------+----------+--------+--------+----------+----------+----------+
| magic | version | kdf_it | kdf_id | salt_len | salt     | nonce_len| ...
| "VLT1"| 0x01    | u32 BE | 0x01   | u8=16    | 16 bytes | u8=12    |
+-------+----------+--------+--------+----------+----------+----------+
| nonce | aad_len | aad    | ct_len (implicit) | ciphertext            |
| 12 B  | u16 BE  |"vault-v1"             | N bytes                 |
+-------+----------+-----------------------+-------------------------+
| tag (AES-GCM, 16 bytes)                                              |
+-----------------------------------------------------------------------+
```

All multi-byte integers are big-endian.

## Testing

```sh
python3 tests/test_vault.py
```

Covers:

- AES-GCM round-trip and tamper detection (ciphertext & tag)
- PBKDF2 stability
- Header pack/unpack
- Init + unlock round-trip
- Wrong-password rejection
- REPL `add entry` flow (with FakeIO)
- Language preference persists across save/reload

## Backups

Treat the `.vault` file like a private SSH key. Copy it to encrypted backup
media only. Losing the master password means losing all entries — there is no
recovery.

## Limitations

- AES-GCM is re-implemented in pure Python; performance is fine for hundreds
  of entries but slow for tens of thousands.
- Plaintext exports are intentional and unprotected; the menu prints a
  warning before writing.
- No two-factor / TOTP generation (the `totp_secret` field exists in the
  schema for future use).