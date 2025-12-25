# bindecrypter/core.py
import gzip
import hashlib
import logging
import re
from base64 import b64decode
from typing import Dict, Tuple

from Crypto.Cipher import AES


LOG = logging.getLogger("bindecrypter")

GARBAGE_BYTES = (
    bytes.fromhex("603A7C7C0760"),
    bytes.fromhex("60230860"),
    bytes.fromhex("6021203A2626082360"),
)


def evp_bytes_to_key(password: bytes, key_len: int, iv_len: int) -> Tuple[bytes, bytes]:
    d = b""
    prev = b""
    while len(d) < key_len + iv_len:
        prev = hashlib.sha256(prev + password).digest()
        d += prev
    return d[:key_len], d[key_len:key_len + iv_len]


def decrypt(ciphertext: bytes, passphrase: bytes) -> bytes:
    key, iv = evp_bytes_to_key(passphrase, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    pad = plaintext[-1]
    return plaintext[:-pad]


def deobf_nonascii(data: bytes) -> bytes:
    for garbage in GARBAGE_BYTES:
        data = data.replace(garbage, b"")

    clean = bytes(
        c for c in data
        if 0x20 <= c <= 0x7E
    )
    return clean


def is_bincrypter(data: bytes) -> bool:
    if not data.startswith(b"#!/bin/sh\n"):
        return False
    rest = data.split(b"\n", 1)[1]
    return b"\n_=" in rest or rest.startswith(b"_=")


def extract_psc(data: bytes) -> Dict[str, bytes]:
    VAR_RE = re.compile(
        rb'^(P|S|C|BCL|BCV)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s#]+))',
        re.MULTILINE
    )

    result: Dict[str, bytes] = {}
    for m in VAR_RE.finditer(data):
        name = m.group(1).decode()
        value = m.group(2) or m.group(3) or m.group(4)
        result[name] = value
    return result


def bindecrypt(path: str) -> str:
    LOG.info("Reading file: %s", path)
    with open(path, "rb") as f:
        data = f.read()

    if not is_bincrypter(data):
        raise ValueError("Not a bincrypter-wrapped file.")

    LOG.info("Bincrypter detected.")

    script_begin = data.find(b"';") + 2
    script_end = data.find(b"\n#")

    clean = deobf_nonascii(data[script_begin:script_end])
    encoded = clean.split(b"echo ")[1].split(b"|")[0]
    decoded = b64decode(encoded)

    psc = extract_psc(decoded)

    if "BCL" in psc or "BCV" in psc:
        raise RuntimeError("BC_LOCK detected, automatic decryption impossible.")

    if "P" not in psc:
        raise RuntimeError("Decryption key P is missing in decryption script. Probably it uses custom user input.")

    LOG.info("Using embedded decryption material.")

    P_raw = b64decode(psc["P"]).strip()
    passphrase = b"C-" + psc["S"] + b"-" + P_raw

    LOG.debug(f"Decrypting payload using key {passphrase}")

    R = int(
        decrypt(b64decode(psc["C"]), passphrase)
        .strip()
        .split(b"=")[1]
    )

    LOG.debug("Payload offset R = %d", R)

    ciphertext = data.split(b"\n")[2][1:]
    ciphertext = (
        ciphertext
        .replace(b"B3", b"\n")
        .replace(b"B1", b"\x00")
        .replace(b"B2", b"B")
    )

    LOG.debug("Ciphertext size: %d bytes", len(ciphertext))

    payload_key = psc["S"] + b"-" + P_raw
    plaintext = decrypt(ciphertext, payload_key)
    executable = gzip.decompress(plaintext[R:])

    out = f"{path}.bindecrypted"
    with open(out, "wb") as f:
        f.write(executable)

    return out
