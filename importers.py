"""Lectura local de exportaciones; nunca crea un TXT descifrado."""
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import csv
import io
import json
from pathlib import Path
import unicodedata
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import zipfile

import vault

MAX_INPUT = 16 * 1024 * 1024
EXTENSIONS = {".json", ".csv", ".tsv", ".xml", ".txt", ".1pux", ".zip", ".lmv"}
NAMES = ("name", "title", "account", "recordtitle", "nombre", "titulo", "servicio")
USERS = ("username", "loginusername", "loginname", "user", "login", "email", "usuario",
         "nombredeusuario", "username2")
PASSWORDS = ("password", "loginpassword", "pass", "pwd", "contrasena")
URLS = ("url", "loginuri", "loginurl", "website", "websiteurl", "webaddress")


def normalized(value):
    return "".join(c for c in unicodedata.normalize("NFKD", value).lower() if c.isalnum())


def value(row, names, default=""):
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return default


@dataclass
class ImportReport:
    source_format: str
    records: list = field(default_factory=list)
    without_password: int = 0
    non_logins: int = 0
    invalid: int = 0
    duplicates: int = 0
    _seen: set = field(default_factory=set, repr=False)

    def add(self, name, username, password, url=""):
        if password is None or password == "":
            self.without_password += 1
            return
        if username is None:
            username = ""
        if name is None or name == "":
            try:
                name = urlparse(url if "://" in url else "//" + url).hostname or "Untitled"
            except (TypeError, ValueError):
                name = "Untitled"
        fields = [name, username, password]
        try:
            if not all(isinstance(s, str) for s in fields):
                raise vault.VaultError("Unsupported field type.")
            vault.validate_record(fields)
        except vault.VaultError:
            self.invalid += 1
            return
        identity = tuple(fields)
        if identity in self._seen:
            self.duplicates += 1
        else:
            self.records.append(fields)
            self._seen.add(identity)

    def finish(self):
        if not self.records:
            raise vault.VaultError(
                "No compatible password accounts found. "
                f"Without password: {self.without_password}; other types: {self.non_logins}; "
                f"out of limits: {self.invalid}.")
        return self


def generic_record(report, item):
    if not isinstance(item, dict):
        report.invalid += 1
        return
    row = {normalized(str(k)): v for k, v in item.items()}
    kind = normalized(str(value(row, ("type", "category"), "")))
    if kind in {"securenote", "note", "creditcard", "identity", "bankaccount", "sshkey"}:
        report.non_logins += 1
        return
    report.add(value(row, NAMES), value(row, USERS), value(row, PASSWORDS), value(row, URLS))


class ExportPasswordRequired(vault.VaultError):
    pass


def decrypt_export(envelope, password):
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    def number(name, limit):
        n = envelope.get(name)
        if type(n) is not int or not 1 <= n <= limit:
            raise vault.VaultError("Unsupported export encryption parameters.")
        return n

    try:
        salt = envelope['salt'].encode('utf-8')
        if not 1 <= len(salt) <= 256:
            raise ValueError()
        secret = password.encode('utf-8')
        if envelope['kdfType'] == 0:
            key = hashlib.pbkdf2_hmac('sha256', secret, salt, number('kdfIterations', 5000000))
        elif envelope['kdfType'] == 1:
            key = Argon2id(salt=hashlib.sha256(salt).digest(), length=32,
                           iterations=number('kdfIterations', 16), lanes=number('kdfParallelism', 16),
                           memory_cost=1024*number('kdfMemory', 256)).derive(secret)
        else:
            raise ValueError()
        def unpack(field):
            value = envelope[field]
            if not value.startswith('2.'):
                raise ValueError()
            iv, body, tag = (base64.b64decode(part, validate=True) for part in value[2:].split('|'))
            mac_key = hmac.digest(key, b'mac\x01', 'sha256')
            if len(iv) != 16 or not hmac.compare_digest(tag, hmac.digest(mac_key, iv+body, 'sha256')):
                raise ValueError()
            return iv, body
        unpack('encKeyValidation_DO_NOT_EDIT')
        iv, body = unpack('data')
        enc_key = hmac.digest(key, b'enc\x01', 'sha256')
        decrypt = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        unpad = padding.PKCS7(128).unpadder()
        return json.loads(unpad.update(decrypt.update(body) + decrypt.finalize()) + unpad.finalize())
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise vault.VaultError("Incorrect export password or unsupported encrypted file.") from exc


def json_records(text, password=None):
    data = json.loads(text)
    if isinstance(data, dict) and data.get('encrypted') is True:
        if data.get('passwordProtected') is not True:
            raise vault.VaultError("In Bitwarden, export as Password protected to open the file here.")
        if password is None:
            raise ExportPasswordRequired("Enter the Bitwarden export password.")
        data = decrypt_export(data, password)
    if isinstance(data, dict) and isinstance(data.get("accounts"), list):
        report = ImportReport("1Password 1PUX")
        for account in data["accounts"]:
            for container in account.get("vaults", []):
                for item in container.get("items", []):
                    if item.get("state") == "archived" or item.get("trashed"):
                        report.non_logins += 1
                        continue
                    details = item.get("details") or {}
                    login_fields = details.get("loginFields") or []
                    fields = {f.get("designation"): f.get("value") for f in login_fields
                              if isinstance(f, dict)}
                    overview = item.get("overview") or {}
                    report.add(overview.get("title"), fields.get("username", ""),
                               fields.get("password"), overview.get("url", ""))
        return report.finish()
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        report = ImportReport("Bitwarden / JSON")
        for item in data["items"]:
            if not isinstance(item, dict):
                report.invalid += 1
                continue
            if isinstance(item.get("login"), dict):
                if item.get("type", 1) not in (1, "1") or item.get("deletedDate"):
                    report.non_logins += 1
                    continue
                login = item["login"]
                report.add(item.get("name"), login.get("username"), login.get("password"))
            elif "type" in item and item["type"] not in (1, "1"):
                report.non_logins += 1
            else:
                generic_record(report, item)
        return report.finish()
    if isinstance(data, dict):
        nested = next((data[k] for k in ("entries", "credentials", "logins", "passwords")
                       if isinstance(data.get(k), list)), None)
        data = nested if nested is not None else [data]
    if not isinstance(data, list):
        raise vault.VaultError("Unsupported JSON structure.")
    report = ImportReport("Compatible JSON")
    for item in data:
        generic_record(report, item)
    return report.finish()


def csv_records(text):
    for delimiter in (",", ";", "\t"):
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
        headings = next(reader, [])
        keys = [normalized(s) for s in headings]
        if not any(k in PASSWORDS for k in keys):
            continue
        if len([k for k in keys if k]) != len(set(k for k in keys if k)):
            raise vault.VaultError("The CSV has duplicate headers.")
        report = ImportReport("Compatible CSV / TSV")
        for fields in reader:
            if not fields or not any(fields):
                continue
            if len(fields) != len(keys):
                report.invalid += 1
                continue
            generic_record(report, dict(zip(keys, fields)))
        return report.finish()
    raise vault.VaultError("Unsupported CSV: a Password column is required.")


def xml_records(text):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise vault.VaultError("XML DTDs and entities are not supported.")
    root = ET.fromstring(text)
    report = ImportReport("KeePass / XML")

    def visit(node):
        for child in node:
            tag = child.tag.rsplit("}", 1)[-1].lower()
            if tag in {"root", "group", "entries", "database"}:
                visit(child)
            elif tag == "entry":
                fields = {}
                protected = False
                for item in child:
                    key = item.tag.rsplit("}", 1)[-1].lower()
                    if key == "string":
                        title, contents = item.findtext("Key", ""), item.find("Value")
                        if contents is not None:
                            if contents.get("Protected", "").lower() == "true":
                                protected = True
                            fields[normalized(title)] = contents.text or ""
                    elif key != "history":
                        fields[normalized(key)] = item.text or ""
                if protected:
                    report.invalid += 1
                else:
                    generic_record(report, fields)
    visit(root)
    return report.finish()


def decode(data):
    return data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")


def read_import(filename, password=None):
    path = Path(filename)
    suffix = path.suffix.lower()
    try:
        if suffix in {".1pux", ".zip"}:
            if path.stat().st_size > MAX_INPUT * 4:
                raise vault.VaultError("The archive exceeds 64 MiB.")
            with zipfile.ZipFile(path) as archive:
                items = archive.infolist()
                if len(items) > 5000:
                    raise vault.VaultError("Too many archive members.")
                chosen = [i for i in items if Path(i.filename).name.lower() == "export.data"]
                if not chosen:
                    chosen = [i for i in items if Path(i.filename).name.lower() == "credentials.csv"]
                if len(chosen) != 1:
                    raise vault.VaultError("Unsupported ZIP: expected 1PUX or credentials.csv.")
                info = chosen[0]
                if info.file_size > MAX_INPUT or info.flag_bits & 1:
                    raise vault.VaultError("Oversized contents or encrypted ZIP.")
                with archive.open(info) as stream:
                    raw = stream.read(MAX_INPUT + 1)
                if len(raw) > MAX_INPUT:
                    raise vault.VaultError("Contents exceed 16 MiB.")
                text = decode(raw)
                return json_records(text) if info.filename.endswith("export.data") else csv_records(text)
        if suffix not in EXTENSIONS or suffix == ".lmv":
            raise vault.VaultError("Unsupported import format.")
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise vault.VaultError("The file exceeds 16 MiB.")
        text = decode(raw)
        if suffix == ".json":
            return json_records(text, password)
        if suffix in {".csv", ".tsv"}:
            return csv_records(text)
        if suffix == ".xml":
            return xml_records(text)
        report = ImportReport("Lockfin TXT")
        for record in vault.parse_text(text):
            report.add(*record)
        return report.finish()
    except (UnicodeError, json.JSONDecodeError, csv.Error, ET.ParseError, zipfile.BadZipFile,
            RecursionError, AttributeError, TypeError, KeyError) as exc:
        raise vault.VaultError("The file is not a supported export or is damaged.") from exc
