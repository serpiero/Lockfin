#!/usr/bin/env python3
"""Boveda de Lockfin. Dependencia: python -m pip install cryptography.

create entradas.txt vault.lmv | add vault.lmv | check vault.lmv
passwd vault.lmv | self-test

Las claves se solicitan en la terminal, nunca como argumentos del proceso.
LMV1 = cabecera autenticada de 40 bytes + AES-256-GCM + etiqueta de 16 bytes.
"""

import argparse
import getpass
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import warnings

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER = struct.Struct("<4sI16s12sI")
MAGIC = b"LMV1"
FAVORITES_MAGIC = b"LMV2"


class FavoriteLogin(list):
    """A starred three-field login. Selection and editing keep its marker."""


ITERATIONS = 600_000
MIN_ITERATIONS = 10_000
MAX_ITERATIONS = 2_000_000
MAX_PAYLOAD = 32_768
MAX_LOGINS = 500


class VaultError(ValueError):
    pass


class OutdatedKDFWarning(UserWarning):
    """La boveda autenticada necesita actualizar su coste de derivacion."""


def validate_master(master):
    if not 8 <= len(master) <= 63 or any(not 32 <= ord(c) <= 126 for c in master):
        raise VaultError("The vault password must contain 8–63 ASCII characters.")
    return master.encode("ascii")


def validate_record(fields):
    if len(fields) != 3 or not fields[0] or not fields[2]:
        raise VaultError("Each account needs a name, optional username and a password.")
    for field in fields:
        if len(field.encode("utf-8")) > 99 or any(ord(c) < 32 or ord(c) == 127 for c in field):
            raise VaultError("Unsupported field: maximum 99 bytes, no control characters.")


def parse_text(text):
    records = []
    for number, line in enumerate(text.split("\n"), 1):
        if line.endswith("\r"):
            line = line[:-1]
        if not line:
            continue
        fields, escaped = [""], False
        for char in line:
            if escaped:
                fields[-1] += char
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == ",":
                fields.append("")
            else:
                fields[-1] += char
        try:
            if escaped:
                raise VaultError("Incomplete escape sequence.")
            validate_record(fields)
        except VaultError as exc:
            raise VaultError(f"Check the format of line {number}.") from exc
        records.append(fields)
    if len(records) > MAX_LOGINS:
        raise VaultError(f"A vault supports up to {MAX_LOGINS} accounts.")
    return records


def serialize(records):
    if len(records) > MAX_LOGINS:
        raise VaultError(f"A vault supports up to {MAX_LOGINS} accounts.")
    lines = []
    for record in records:
        validate_record(record)
        fields = [s.replace("\\", "\\\\").replace(",", "\\,") for s in record]
        lines.append(",".join(fields))
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    if len(payload) > MAX_PAYLOAD:
        raise VaultError("The vault exceeds the 32 KiB limit.")
    return payload


def seal(records, master):
    password = validate_master(master)
    favorites = [r for r in records if isinstance(r, FavoriteLogin)]
    if favorites:
        ordered = favorites + [r for r in records if not isinstance(r, FavoriteLogin)]
        payload = len(favorites).to_bytes(2, "little") + serialize(ordered)
    else:
        payload = serialize(records)
    salt, nonce = os.urandom(16), os.urandom(12)
    header = HEADER.pack(FAVORITES_MAGIC if favorites else MAGIC, ITERATIONS, salt, nonce, len(payload))
    key = hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS, 32)
    return header + AESGCM(key).encrypt(nonce, payload, header)


def unseal(blob, master):
    password = validate_master(master)
    if not HEADER.size + 17 <= len(blob) <= HEADER.size + MAX_PAYLOAD + 18:
        raise VaultError("Invalid vault size.")
    magic, iterations, salt, nonce, length = HEADER.unpack(blob[:HEADER.size])
    if (magic not in (MAGIC, FAVORITES_MAGIC) or not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS or
            not 1 <= length - (2 if magic == FAVORITES_MAGIC else 0) <= MAX_PAYLOAD or len(blob) != HEADER.size + length + 16):
        raise VaultError("Invalid vault header.")
    key = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, 32)
    try:
        plaintext = AESGCM(key).decrypt(nonce, blob[HEADER.size:], blob[:HEADER.size])
    except InvalidTag as exc:
        raise VaultError("Could not unlock this vault. Check its master password and that the copy is complete.") from exc
    try:
        count = int.from_bytes(plaintext[:2], "little") if magic == FAVORITES_MAGIC else 0
        text = plaintext[2:] if magic == FAVORITES_MAGIC else plaintext
        records = parse_text(text.decode("utf-8"))
        if count > len(records):
            raise VaultError("Invalid favorite count.")
        records[:count] = [FavoriteLogin(record) for record in records[:count]]
        if iterations < ITERATIONS:
            warnings.warn(
                f"Vault uses {iterations:,} KDF iterations; the current cost is {ITERATIONS:,}. "
                "Run 'python vault.py passwd <vault.lmv>' to re-encrypt it.",
                OutdatedKDFWarning,
                stacklevel=2,
            )
        return records
    except UnicodeError as exc:
        raise VaultError("Invalid vault contents.") from exc


def read_blob(path):
    with path.open("rb") as source:
        blob = source.read(HEADER.size + MAX_PAYLOAD + 19)
    if len(blob) > HEADER.size + MAX_PAYLOAD + 18:
        raise VaultError("The vault exceeds the supported size.")
    return blob


def atomic_write(path, blob, replace=False, previous=None):
    path = path.resolve()
    if previous is not None and read_blob(path) != previous:
        raise VaultError("The file changed while editing; it was not overwritten.")
    fd, name = tempfile.mkstemp(prefix=".lmv-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.chmod(name, 0o600)
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, path)
        else:
            os.link(name, path)  # Exclusivo: falla si ya existe el destino.
    finally:
        if os.path.exists(name):
            os.unlink(name)


def ask_master(confirm=False):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        master = getpass.getpass("Vault password: ")
        validate_master(master)
        if confirm and master != getpass.getpass("Confirm password: "):
            raise VaultError("Passwords do not match.")
    return master


def self_test():
    expected = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    assert hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, 32).hex() == expected
    records = [["Demo, uno", "user\\demo", "Ficticia!_123"], ["Demo dos", "", "OtraFicticia"]]
    master = "SoloPruebas123"
    blob = seal(records, master)
    assert HEADER.unpack_from(blob)[1] == ITERATIONS
    assert unseal(blob, master) == records
    assert b"Ficticia!_123" not in blob and b"user\\demo" not in blob
    assert seal(records, master) != blob
    for offset in (0, 4, 8, 24, 36, 40, len(blob) - 1):
        damaged = bytearray(blob)
        damaged[offset] ^= 1
        try:
            unseal(damaged, master)
        except VaultError:
            pass
        else:
            raise AssertionError("Se acepto una boveda alterada.")
    for bad in (b"", blob[:39], blob[:55], blob[:-1]):
        try:
            unseal(bad, master)
        except VaultError:
            pass
        else:
            raise AssertionError("Se acepto una boveda truncada.")
    try:
        unseal(blob, "ClaveEquivocada")
    except VaultError:
        pass
    else:
        raise AssertionError("Se acepto una clave incorrecta.")
    assert parse_text(serialize(records).decode()) == records
    edge = [["N" * 99, "\\" * 99, "," * 99]]
    assert unseal(seal(edge, master), master) == edge
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "vault.lmv"
        atomic_write(path, blob)
        try:
            atomic_write(path, seal(records, master))
        except FileExistsError:
            pass
        else:
            raise AssertionError("Se sobrescribio una boveda existente.")
        assert read_blob(path) == blob
    print("Self-test passed: encryption, incorrect passwords, tampering, limits and writes.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Convert TXT into a new encrypted vault")
    create.add_argument("source", type=Path)
    create.add_argument("vault", type=Path)
    for name in ("add", "check", "passwd"):
        commands.add_parser(name).add_argument("vault", type=Path)
    commands.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return
    if args.command == "create":
        if args.vault.exists():
            raise VaultError("The destination exists; choose another name.")
        with args.source.open("r", encoding="utf-8-sig", newline="") as source:
            text = source.read(MAX_PAYLOAD + 1)
        if len(text.encode("utf-8")) > MAX_PAYLOAD:
            raise VaultError("The TXT exceeds the 32 KiB limit.")
        records = parse_text(text)
        atomic_write(args.vault, seal(records, ask_master(confirm=True)))
        print(f"Vault created: {len(records)} accounts. The original TXT is preserved.")
        return
    original = read_blob(args.vault)
    master = ask_master()
    records = unseal(original, master)
    if args.command == "check":
        print(f"Vault verified: {len(records)} accounts.")
        iterations = HEADER.unpack_from(original)[1]
        status = "below current" if iterations < ITERATIONS else "meets current cost"
        print(f"KDF iterations: {iterations:,} ({status}; current: {ITERATIONS:,}).")
        return
    if args.command == "add":
        name = input("Account name: ")
        username = input("Username: ")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Account password: ")
        records.append([name, username, password])
    elif args.command == "passwd":
        print("Choose the new vault password.")
        master = ask_master(confirm=True)
    atomic_write(args.vault, seal(records, master), replace=True, previous=original)
    print(f"Vault updated: {len(records)} accounts.")


if __name__ == "__main__":
    try:
        main()
    except (VaultError, OSError, getpass.GetPassWarning, UnicodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("Cancelled; no changes saved.", file=sys.stderr)
        sys.exit(1)
