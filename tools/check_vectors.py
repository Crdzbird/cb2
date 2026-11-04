"""An independent check of the cb2 test vectors against docs/PROTOCOL.md.

This program is a second implementation of the cb2 token formats, written
from the protocol document alone and never from the C++ reference. It
reproduces every cb2.local token, every claims-layer local token and every
kcb2 key string from the recorded inputs, recomputes and compares every
intermediate value the vectors record, verifies every cb2.public token,
and checks that every failure, tamper, weak-key, rejected-secret-key and
claims vector yields the recorded verdict. It exits 0 when every check
passes and 1 otherwise.

Primitives come from two PyPI packages: blake3 for BLAKE3 in hash and
keyed mode, and pynacl for Ed25519 and for libsodium's HChaCha20 and
ChaCha20, which pynacl does not wrap in Python but which its bundled
libsodium exports, so the XChaCha20 of section 2 is composed from them
through ctypes exactly as the document describes. ML-DSA-65 is taken from
the pure-Python dilithium-py package when it is installed; without it the
ML-DSA half of cb2.public is not evaluated, every check that depends on it
alone is reported as skipped rather than passed, and a note says so.

Run as

    python3 -I tools/check_vectors.py [vector-directory]

with the directory defaulting to tests/vectors beside this file's parent.
"""

import ctypes
import hmac
import json
import os
import re
import sys

import blake3
import nacl._sodium
import nacl.exceptions
import nacl.signing

LOCAL_HEADER = b"cb2.local."
PUBLIC_HEADER = b"cb2.public."
WRAP_HEADER = b"kcb2.local-wrap."
ED25519_SIGNATURE_BYTES = 64
MLDSA_SIGNATURE_BYTES = 3309
MLDSA_PUBLIC_BYTES = 1952
MLDSA_SECRET_BYTES = 4032
PUBLIC_KEY_BYTES = 32 + MLDSA_PUBLIC_BYTES
SECRET_KEY_BYTES = 64 + MLDSA_SECRET_BYTES + MLDSA_PUBLIC_BYTES
SIGNATURE_BYTES = ED25519_SIGNATURE_BYTES + MLDSA_SIGNATURE_BYTES
SELF_TEST_CONTEXT = b"kcb2.secret.self-test"
DEFAULT_MAX_TOKEN_BYTES = 16384
REGISTERED = ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
TIME_CLAIMS = ("exp", "nbf", "iat")
IDENTIFIER_CLAIMS = ("iss", "sub", "aud", "jti")


class Verdict(Exception):
    """A rejection carrying one of the verdict names of section 10."""

    def __init__(self, name):
        super().__init__(name)
        self.name = name


def invalid():
    """Raise the single token-dependent verdict of section 1."""
    raise Verdict("invalid")


def load_mldsa():
    """Return the ML-DSA-65 implementation when dilithium-py is installed."""
    try:
        from dilithium_py.ml_dsa import ML_DSA_65
    except ImportError:
        return None
    return ML_DSA_65


def load_sodium():
    """Bind HChaCha20 and the original ChaCha20 stream from pynacl's libsodium."""
    lib = ctypes.CDLL(nacl._sodium.__file__)
    try:
        hchacha = lib.crypto_core_hchacha20
        chacha = lib.crypto_stream_chacha20_xor
    except AttributeError:
        return None
    hchacha.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
    hchacha.restype = ctypes.c_int
    chacha.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
    chacha.restype = ctypes.c_int
    return hchacha, chacha


SODIUM = load_sodium()


def hchacha20(key, nonce16):
    """HChaCha20 of a 32-byte key and 16 nonce bytes, 32 bytes out."""
    out = ctypes.create_string_buffer(32)
    if SODIUM[0](out, nonce16, key, None) != 0:
        raise Verdict("internal")
    return out.raw


def xchacha20(key, nonce24, message):
    """XChaCha20 as section 2 defines it, block counter starting at 0."""
    subkey = hchacha20(key, nonce24[:16])
    out = ctypes.create_string_buffer(max(len(message), 1))
    if SODIUM[1](out, message, len(message), nonce24[16:], subkey) != 0:
        raise Verdict("internal")
    return out.raw[: len(message)]


def blake3_keyed(key, message, length):
    """BLAKE3 keyed mode with extendable output."""
    return blake3.blake3(message, key=key).digest(length=length)


def blake3_hash(message, length):
    """BLAKE3 hash mode with extendable output."""
    return blake3.blake3(message).digest(length=length)


def ed25519_sign(ed_sk, message):
    """RFC 8032 Ed25519 signature from a 64-byte seed-plus-public-key secret."""
    return nacl.signing.SigningKey(ed_sk[:32]).sign(message).signature


def ed25519_verify(ed_pk, message, signature):
    """RFC 8032 Ed25519 verification, False on any failure."""
    try:
        nacl.signing.VerifyKey(ed_pk).verify(message, signature)
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, ValueError):
        return False
    return True


def le64(n):
    """The 8-byte little-endian encoding of section 3.1."""
    if n >= 1 << 63:
        raise Verdict("argument")
    return n.to_bytes(8, "little")


def pae(*pieces):
    """The pre-authentication encoding of section 3.2."""
    out = le64(len(pieces))
    for piece in pieces:
        out += le64(len(piece)) + piece
    return out


B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B64_VALUE = {c: i for i, c in enumerate(B64_ALPHABET)}


def b64_encode(data):
    """RFC 4648 section 5 without padding."""
    out = bytearray()
    for k in range(0, len(data) - len(data) % 3, 3):
        n = int.from_bytes(data[k : k + 3], "big")
        out += bytes(B64_ALPHABET[(n >> s) & 63] for s in (18, 12, 6, 0))
    rest = data[len(data) - len(data) % 3 :]
    if len(rest) == 1:
        n = rest[0] << 16
        out += bytes(B64_ALPHABET[(n >> s) & 63] for s in (18, 12))
    if len(rest) == 2:
        n = int.from_bytes(rest, "big") << 8
        out += bytes(B64_ALPHABET[(n >> s) & 63] for s in (18, 12, 6))
    return bytes(out)


def b64_decode(text):
    """The strict decoder of section 3.3; raises Verdict on any violation."""
    if len(text) % 4 == 1:
        invalid()
    try:
        values = [B64_VALUE[c] for c in text]
    except KeyError:
        invalid()
    out = bytearray()
    for k in range(0, len(values) - len(values) % 4, 4):
        n = (values[k] << 18) | (values[k + 1] << 12) | (values[k + 2] << 6) | values[k + 3]
        out += n.to_bytes(3, "big")
    rest = values[len(values) - len(values) % 4 :]
    if len(rest) == 2:
        if rest[1] & 0x0F:
            invalid()
        out.append((rest[0] << 2) | (rest[1] >> 4))
    if len(rest) == 3:
        if rest[2] & 0x03:
            invalid()
        n = (rest[0] << 12) | (rest[1] << 6) | rest[2]
        out += (n >> 2).to_bytes(2, "big")
    return bytes(out)


def b64len(x):
    """The length of the encoding of x bytes, section 3.3."""
    return 4 * (x // 3) + (0 if x % 3 == 0 else x % 3 + 1)


def constant_time_equal(a, b):
    """Equality that does not leak how many bytes matched."""
    return hmac.compare_digest(a, b)


def import_local_key(key):
    """Section 5.1: 32 bytes, not all equal."""
    if len(key) != 32 or key == bytes([key[0]]) * 32:
        raise Verdict("argument")
    return key


def local_split(key, nonce, header):
    """The keyed BLAKE3 key split of section 5.2."""
    out = blake3_keyed(key, header + nonce, 88)
    return out[:32], out[32:56], out[56:88]


def local_seal(key, nonce, message, footer, implicit, header=LOCAL_HEADER):
    """Section 5.2, returning every intermediate value and the token."""
    ek, n2, ak = local_split(key, nonce, header)
    ciphertext = xchacha20(ek, n2, message)
    pre_auth = pae(header, nonce, ciphertext, footer, implicit)
    tag = blake3_keyed(ak, pre_auth, 32)
    token = header + b64_encode(nonce + ciphertext + tag)
    if footer:
        token += b"." + b64_encode(footer)
    return {"ek": ek, "n2": n2, "ak": ak, "ciphertext": ciphertext, "pae": pre_auth, "tag": tag, "token": token}


def split_token(token, header, footer):
    """Steps 1 to 4 of section 5.3; returns the decoded body."""
    if not token.startswith(header) or len(token) <= len(header):
        invalid()
    rest = token[len(header) :]
    body_text, dot, footer_text = rest.partition(b".")
    if dot and not footer_text:
        invalid()
    if bool(dot) != bool(footer):
        invalid()
    body = b64_decode(body_text)
    if dot:
        carried = b64_decode(footer_text)
        if len(carried) != len(footer) or not constant_time_equal(carried, footer):
            invalid()
    return body


def local_open(token, key, footer, implicit, header=LOCAL_HEADER):
    """Section 5.3; returns the message or raises invalid."""
    body = split_token(token, header, footer)
    if len(body) < 64:
        invalid()
    nonce, ciphertext, tag = body[:32], body[32:-32], body[-32:]
    ek, n2, ak = local_split(key, nonce, header)
    expected = blake3_keyed(ak, pae(header, nonce, ciphertext, footer, implicit), 32)
    if not constant_time_equal(expected, tag):
        invalid()
    return xchacha20(ek, n2, ciphertext)


def import_public_key(pk):
    """Section 6.1: 1984 bytes."""
    if len(pk) != PUBLIC_KEY_BYTES:
        raise Verdict("argument")
    return pk


def import_secret_key(sk, mldsa):
    """Section 6.1 with the consistency check; returns whether ML-DSA was probed."""
    if len(sk) != SECRET_KEY_BYTES:
        raise Verdict("argument")
    ed_sk, ml_sk, ml_pk = sk[:64], sk[64 : 64 + MLDSA_SECRET_BYTES], sk[64 + MLDSA_SECRET_BYTES :]
    derived = bytes(nacl.signing.SigningKey(ed_sk[:32]).verify_key)
    if not constant_time_equal(derived, ed_sk[32:]):
        raise Verdict("argument")
    if mldsa is None:
        return False
    try:
        probe = mldsa.sign(ml_sk, b"probe", ctx=SELF_TEST_CONTEXT)
        ok = mldsa.verify(ml_pk, b"probe", probe, ctx=SELF_TEST_CONTEXT)
    except Exception:
        ok = False
    if not ok:
        raise Verdict("argument")
    return True


def public_sign(sk, message, footer, implicit, mldsa):
    """Section 6.2; the token is None when ML-DSA-65 is not available."""
    ed_sk, ml_sk = sk[:64], sk[64 : 64 + MLDSA_SECRET_BYTES]
    m2 = pae(PUBLIC_HEADER, message, footer, implicit)
    ed_sig = ed25519_sign(ed_sk, m2)
    token = None
    if mldsa is not None:
        ml_sig = mldsa.sign(ml_sk, m2, ctx=PUBLIC_HEADER)
        token = PUBLIC_HEADER + b64_encode(message + ed_sig + ml_sig)
        if footer:
            token += b"." + b64_encode(footer)
    return {"pae": m2, "ed25519-signature": ed_sig, "token": token}


def public_verify(token, pk, footer, implicit, mldsa):
    """Section 6.3; returns (message, ml_checked) or raises invalid."""
    body = split_token(token, PUBLIC_HEADER, footer)
    if len(body) < SIGNATURE_BYTES:
        invalid()
    message, sig = body[:-SIGNATURE_BYTES], body[-SIGNATURE_BYTES:]
    m2 = pae(PUBLIC_HEADER, message, footer, implicit)
    ed_ok = ed25519_verify(pk[:32], m2, sig[:ED25519_SIGNATURE_BYTES])
    ml_ok = True
    if mldsa is not None:
        ml_ok = mldsa.verify(pk[32:], m2, sig[ED25519_SIGNATURE_BYTES:], ctx=PUBLIC_HEADER)
    if not (ed_ok and ml_ok):
        invalid()
    return message, mldsa is not None


def kcb2_local(key):
    """The kcb2.local string of section 7."""
    return b"kcb2.local." + b64_encode(key)


def kcb2_lid(key):
    """The kcb2.lid string of section 7, a hash over the full key string."""
    return b"kcb2.lid." + b64_encode(blake3_hash(b"kcb2.lid." + kcb2_local(key), 33))


def kcb2_public(pk):
    """The kcb2.public string of section 7."""
    return b"kcb2.public." + b64_encode(pk)


def kcb2_pid(pk):
    """The kcb2.pid string of section 7."""
    return b"kcb2.pid." + b64_encode(blake3_hash(b"kcb2.pid." + kcb2_public(pk), 33))


def kcb2_secret(sk):
    """The kcb2.secret string of section 7."""
    return b"kcb2.secret." + b64_encode(sk)


def parse_key_string(text, prefix, total_length):
    """Decode a key string strictly, requiring the exact length of the table."""
    if len(text) != total_length or not text.startswith(prefix):
        raise Verdict("argument")
    return b64_decode(text[len(prefix) :])


def key_wrap(wrapping, key, nonce):
    """kcb2.local-wrap: section 5 under the 16-byte wrap header."""
    return local_seal(wrapping, nonce, key, b"", b"", WRAP_HEADER)["token"]


def key_unwrap(text, wrapping):
    """Open a kcb2.local-wrap string to the 32 key bytes."""
    if len(text) != 144:
        invalid()
    key = local_open(text, wrapping, b"", b"", WRAP_HEADER)
    if len(key) != 32:
        invalid()
    return key


class JsonNumber:
    """A JSON number kept as its text, as section 9.2 requires."""

    def __init__(self, text):
        self.text = text


class JsonLiteral:
    """One of true, false and null."""

    def __init__(self, text):
        self.text = text


class JsonObject:
    """A JSON object as an ordered list of (name, value) members."""

    def __init__(self):
        self.members = []

    def get(self, name):
        """The value of a member, or None."""
        for key, value in self.members:
            if key == name:
                return value
        return None


class JsonError(Exception):
    """A violation of the reader rules of section 9.2."""


NUMBER_RE = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
MAX_DEPTH = 16


class JsonReader:
    """The strict RFC 8259 reader of section 9.2 over a byte string."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def parse(self):
        """Read exactly one value and nothing else."""
        value = self.value(1)
        self.skip_space()
        if self.pos != len(self.data):
            raise JsonError("trailing bytes")
        return value

    def skip_space(self):
        """Skip the four JSON whitespace characters."""
        while self.pos < len(self.data) and self.data[self.pos] in b" \t\n\r":
            self.pos += 1

    def peek(self):
        """The next byte, or -1 at the end."""
        return self.data[self.pos] if self.pos < len(self.data) else -1

    def expect(self, byte):
        """Consume one required byte."""
        if self.peek() != byte:
            raise JsonError("expected %r" % bytes([byte]))
        self.pos += 1

    def value(self, depth):
        """Read any value; depth counts the containers enclosing it, plus one."""
        self.skip_space()
        c = self.peek()
        if c == 0x7B:
            return self.object(depth)
        if c == 0x5B:
            return self.array(depth)
        if c == 0x22:
            return self.string()
        if c == 0x2D or 0x30 <= c <= 0x39:
            return self.number()
        for literal in (b"true", b"false", b"null"):
            if self.data.startswith(literal, self.pos):
                self.pos += len(literal)
                return JsonLiteral(literal.decode("ascii"))
        raise JsonError("unexpected byte")

    def object(self, depth):
        """Read an object, refusing duplicate names and excess depth."""
        if depth > MAX_DEPTH:
            raise JsonError("too deep")
        self.pos += 1
        obj = JsonObject()
        self.skip_space()
        if self.peek() == 0x7D:
            self.pos += 1
            return obj
        names = set()
        while True:
            self.skip_space()
            self.expect(0x22)
            self.pos -= 1
            name = self.string()
            if name in names:
                raise JsonError("duplicate member")
            names.add(name)
            self.skip_space()
            self.expect(0x3A)
            obj.members.append((name, self.value(depth + 1)))
            self.skip_space()
            c = self.peek()
            self.pos += 1
            if c == 0x7D:
                return obj
            if c != 0x2C:
                raise JsonError("expected , or }")

    def array(self, depth):
        """Read an array, refusing excess depth."""
        if depth > MAX_DEPTH:
            raise JsonError("too deep")
        self.pos += 1
        items = []
        self.skip_space()
        if self.peek() == 0x5D:
            self.pos += 1
            return items
        while True:
            items.append(self.value(depth + 1))
            self.skip_space()
            c = self.peek()
            self.pos += 1
            if c == 0x5D:
                return items
            if c != 0x2C:
                raise JsonError("expected , or ]")

    def number(self):
        """Read a number matching the RFC 8259 grammar and keep its text."""
        match = NUMBER_RE.match(self.data, self.pos)
        if match is None:
            raise JsonError("bad number")
        self.pos = match.end()
        return JsonNumber(match.group().decode("ascii"))

    def string(self):
        """Read a string, resolving escapes and insisting on well-formed UTF-8."""
        self.pos += 1
        out = []
        while True:
            start = self.pos
            while self.pos < len(self.data) and self.data[self.pos] not in b'"\\' and self.data[self.pos] >= 0x20:
                self.pos += 1
            if self.pos > start:
                try:
                    out.append(self.data[start : self.pos].decode("utf-8"))
                except UnicodeDecodeError:
                    raise JsonError("bad utf-8")
            c = self.peek()
            self.pos += 1
            if c == 0x22:
                return "".join(out)
            if c != 0x5C:
                raise JsonError("control character or end of input in string")
            out.append(self.escape())

    def escape(self):
        """Read the escape after a backslash."""
        c = self.peek()
        self.pos += 1
        simple = {0x22: '"', 0x5C: "\\", 0x2F: "/", 0x62: "\b", 0x66: "\f", 0x6E: "\n", 0x72: "\r", 0x74: "\t"}
        if c in simple:
            return simple[c]
        if c != 0x75:
            raise JsonError("bad escape")
        unit = self.hex4()
        if 0xDC00 <= unit <= 0xDFFF:
            raise JsonError("unpaired low surrogate")
        if 0xD800 <= unit <= 0xDBFF:
            if not self.data.startswith(b"\\u", self.pos):
                raise JsonError("unpaired high surrogate")
            self.pos += 2
            low = self.hex4()
            if not 0xDC00 <= low <= 0xDFFF:
                raise JsonError("unpaired high surrogate")
            unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
        return chr(unit)

    def hex4(self):
        """Four hexadecimal digits of a \\u escape."""
        digits = self.data[self.pos : self.pos + 4]
        if len(digits) != 4 or not re.fullmatch(rb"[0-9a-fA-F]{4}", digits):
            raise JsonError("bad \\u escape")
        self.pos += 4
        return int(digits, 16)


def write_string(text):
    """The issuer's string spelling of section 9.1."""
    out = bytearray(b'"')
    for ch in text:
        cp = ord(ch)
        if ch == '"':
            out += b'\\"'
        elif ch == "\\":
            out += b"\\\\"
        elif cp in (0x08, 0x0C, 0x0A, 0x0D, 0x09):
            out += {0x08: b"\\b", 0x0C: b"\\f", 0x0A: b"\\n", 0x0D: b"\\r", 0x09: b"\\t"}[cp]
        elif cp < 0x20:
            out += b"\\u%04x" % cp
        else:
            out += ch.encode("utf-8")
    out += b'"'
    return bytes(out)


def write_value(value):
    """Write any JSON value with no whitespace outside strings."""
    if isinstance(value, str):
        return write_string(value)
    if isinstance(value, (JsonNumber, JsonLiteral)):
        return value.text.encode("ascii")
    if isinstance(value, JsonObject):
        return b"{" + b",".join(write_string(k) + b":" + write_value(v) for k, v in value.members) + b"}"
    return b"[" + b",".join(write_value(v) for v in value) + b"]"


DISALLOWED_RANGES = (
    (0x0000, 0x001F), (0x007F, 0x009F),
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
    (0xFDD0, 0xFDEF),
    (0xE000, 0xF8FF), (0xF0000, 0x10FFFF),
)


def identifier_ok(text):
    """The identifier policy of section 9.4 on a decoded string."""
    for ch in text:
        cp = ord(ch)
        if cp & 0xFFFE == 0xFFFE:
            return False
        for low, high in DISALLOWED_RANGES:
            if low <= cp <= high:
                return False
    return True


RFC3339_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})")


def days_from_civil(y, m, d):
    """Days since 1970-01-01 of a proleptic Gregorian date."""
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def civil_from_days(z):
    """The inverse of days_from_civil."""
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return y + (m <= 2), m, d


def days_in_month(y, m):
    """The length of a month, leap years included."""
    if m == 2:
        return 29 if (y % 4 == 0 and y % 100 != 0) or y % 400 == 0 else 28
    return 30 if m in (4, 6, 9, 11) else 31


def parse_rfc3339(text):
    """Section 9.3: the instant in Unix seconds, or None when not accepted."""
    match = RFC3339_RE.fullmatch(text)
    if match is None:
        return None
    y, mo, d, h, mi, s = (int(match.group(k)) for k in range(1, 7))
    zone = match.group(7)
    if not (1 <= mo <= 12 and 1 <= d <= days_in_month(y, mo) and h <= 23 and mi <= 59 and s <= 60):
        return None
    offset = 0
    if zone not in ("Z", "z"):
        oh, om = int(zone[1:3]), int(zone[4:6])
        if oh > 23 or om > 59:
            return None
        offset = (oh * 3600 + om * 60) * (1 if zone[0] == "+" else -1)
    return days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s - offset


def format_rfc3339(instant):
    """Section 9.3: the produced form."""
    days, rest = divmod(instant, 86400)
    y, m, d = civil_from_days(days)
    return "%04d-%02d-%02dT%02d:%02d:%02d+00:00" % (y, m, d, rest // 3600, rest % 3600 // 60, rest % 60)


class Claims:
    """The registered claims as decoded strings and the custom claims in order."""

    def __init__(self):
        self.registered = {}
        self.custom = []

    def time(self, name):
        """The instant of a time claim, or None when absent."""
        value = self.registered.get(name)
        return None if value is None else parse_rfc3339(value)

    def to_json(self):
        """The canonical payload text of section 9.1."""
        members = []
        for name in REGISTERED:
            if name in self.registered:
                value = self.registered[name]
                if name in TIME_CLAIMS:
                    value = format_rfc3339(parse_rfc3339(value))
                members.append(write_string(name) + b":" + write_string(value))
        for name, value in self.custom:
            members.append(write_string(name) + b":" + write_value(value))
        return b"{" + b",".join(members) + b"}"


def parse_claims(payload):
    """Section 9.6 step 3: the reader, then the identifier policy."""
    try:
        root = JsonReader(payload).parse()
    except JsonError:
        raise Verdict("claims_malformed")
    if not isinstance(root, JsonObject):
        raise Verdict("claims_malformed")
    claims = Claims()
    for name, value in root.members:
        if name in REGISTERED:
            if not isinstance(value, str):
                raise Verdict("claims_malformed")
            if name in TIME_CLAIMS and parse_rfc3339(value) is None:
                raise Verdict("claims_malformed")
            if name in IDENTIFIER_CLAIMS and not identifier_ok(value):
                raise Verdict("claims_malformed")
            claims.registered[name] = value
        else:
            if not identifier_ok(name):
                raise Verdict("claims_malformed")
            claims.custom.append((name, value))
    return claims


def footer_for(key_id):
    """Section 8: the key id binding, or no footer for a key without an id."""
    if key_id is None:
        return b""
    return b'{"kid":' + write_string(key_id) + b"}"


class Rules:
    """The verifier rules of section 9.5, read from a vector's rules object."""

    def __init__(self, spec):
        self.now = spec["now"]
        self.skew = spec.get("clock-skew", 0)
        self.require_exp = spec.get("require-exp", True)
        self.issuer = spec.get("issuer")
        self.audience = spec.get("audience")
        self.subject = spec.get("subject")
        self.any_issuer = not spec.get("require-issuer", True)
        self.any_audience = not spec.get("require-audience", True)
        self.max_token_bytes = spec.get("max-token-bytes", DEFAULT_MAX_TOKEN_BYTES)
        self.seen_jti = spec.get("seen-jti")

    def complete(self):
        """Section 9.5: an expectation or an explicit allowance for both."""
        return (self.issuer is not None or self.any_issuer) and (self.audience is not None or self.any_audience)

    def check(self, claims):
        """Section 9.6 step 4; returns a verdict name or ok."""
        t, s = self.now, self.skew
        exp = claims.time("exp")
        if exp is None and self.require_exp:
            return "missing_exp"
        if exp is not None and exp <= t - s:
            return "expired"
        nbf = claims.time("nbf")
        if nbf is not None and nbf > t + s:
            return "not_yet_valid"
        iat = claims.time("iat")
        if iat is not None and iat > t + s:
            return "issued_in_future"
        for name, expected, verdict in (
            ("iss", self.issuer, "issuer_mismatch"),
            ("aud", self.audience, "audience_mismatch"),
            ("sub", self.subject, "subject_mismatch"),
        ):
            if expected is None:
                continue
            actual = claims.registered.get(name)
            if actual is None or not constant_time_equal(actual.encode("utf-8"), expected.encode("utf-8")):
                return verdict
        if self.seen_jti is not None:
            jti = claims.registered.get("jti")
            if jti is None:
                return "missing_jti"
            if jti in self.seen_jti:
                return "replayed"
        return "ok"


def open_claims(token, authenticate, verifier_key_id, rules):
    """Section 9.6 in order; returns (verdict, claims or None)."""
    if not rules.complete():
        return "rules_incomplete", None
    if verifier_key_id is not None and not identifier_ok(verifier_key_id):
        return "argument", None
    if len(token) > rules.max_token_bytes:
        return "too_large", None
    try:
        payload = authenticate(footer_for(verifier_key_id))
    except Verdict as verdict:
        return verdict.name, None
    try:
        claims = parse_claims(payload)
    except Verdict as verdict:
        return verdict.name, None
    verdict = rules.check(claims)
    return verdict, claims if verdict == "ok" else None


class Report:
    """Counts of passed, failed and skipped checks with their messages."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.notes = []

    def check(self, name, condition, detail=""):
        """Record one check."""
        if condition:
            self.passed += 1
        else:
            self.failed += 1
            print("FAIL %s%s" % (name, ": " + detail if detail else ""))
        return condition

    def skip(self, name, why):
        """Record a check that could not be evaluated."""
        self.skipped += 1
        self.notes.append("skipped %s: %s" % (name, why))

    def snapshot(self):
        """The counts so far, for section reporting."""
        return (self.passed + self.failed, self.failed)

    def section(self, title, before):
        """Print the result of one group of checks since a snapshot."""
        print("%s: %d checks, %d failed" % (title, self.passed + self.failed - before[0], self.failed - before[1]))


def utf8(text):
    """A vector string field as the byte string it names."""
    return text.encode("utf-8")


def unhex(text):
    """A vector hex field as bytes."""
    return bytes.fromhex(text)


def expect_verdict(report, name, fn, expected):
    """Run fn and check that it raises the expected verdict."""
    try:
        fn()
    except Verdict as verdict:
        return report.check(name, verdict.name == expected, "verdict %s, expected %s" % (verdict.name, expected))
    return report.check(name, False, "accepted, expected %s" % expected)


def check_decoder(report):
    """Appendix C item 6: the strict decoder on inputs no vector carries."""
    rejected = (
        (b"AA==", "padding"), (b"AA A", "whitespace"), (b"A", "length 1 mod 4"),
        (b"AB", "unused bits, 2 mod 4"), (b"AAB", "unused bits, 3 mod 4"),
        (b"A+AA", "plus"), (b"AA\n", "line break"),
    )
    for text, why in rejected:
        expect_verdict(report, "decoder rejects %s" % why, lambda: b64_decode(text), "invalid")
    report.check("decoder accepts AQ", b64_decode(b"AQ") == b"\x01")
    report.check("decoder accepts AAE", b64_decode(b"AAE") == b"\x00\x01")
    for n in range(0, 10):
        report.check("b64len(%d)" % n, b64len(n) == len(b64_encode(bytes(n))))
    probe = bytes(range(32))
    nonce = unhex("000000090000004a0000000031415927")
    report.check("HChaCha20 test vector", hchacha20(probe, nonce) == unhex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"))


def check_local_success(report, vector):
    """Appendix A.1 success vector: reproduce, compare every value, open."""
    name = vector["name"]
    key = import_local_key(unhex(vector["key"]))
    footer, implicit = utf8(vector["footer"]), utf8(vector["implicit-assertion"])
    payload = utf8(vector["payload"])
    sealed = local_seal(key, unhex(vector["nonce"]), payload, footer, implicit)
    for field in ("ek", "n2", "ak", "ciphertext", "pae", "tag"):
        if not report.check("%s %s" % (name, field), sealed[field] == unhex(vector[field]), "got %s" % sealed[field].hex()):
            return
    token = utf8(vector["token"])
    if not report.check("%s token" % name, sealed["token"] == token, "got %s" % sealed["token"].decode()):
        return
    expected_len = 10 + b64len(64 + len(payload)) + (1 + b64len(len(footer)) if footer else 0)
    report.check("%s token length formula" % name, len(token) == expected_len)
    try:
        opened = local_open(token, key, footer, implicit)
    except Verdict as verdict:
        report.check("%s open" % name, False, "verdict %s" % verdict.name)
        return
    report.check("%s open" % name, opened == payload)


def check_local(report, doc):
    """Every member of cb2_local.json."""
    before = report.snapshot()
    for vector in doc["tests"]:
        name = vector["name"]
        if not vector["expect-fail"]:
            check_local_success(report, vector)
            continue
        key = unhex(vector["key"])
        footer, implicit = utf8(vector["footer"]), utf8(vector["implicit-assertion"])
        expect_verdict(report, "%s (%s)" % (name, vector["reason"]), lambda: local_open(utf8(vector["token"]), key, footer, implicit), "invalid")
    tamper = doc["tamper"]
    key = unhex(tamper["key"])
    footer, implicit = utf8(tamper["footer"]), utf8(tamper["implicit-assertion"])
    try:
        report.check("local tamper base opens", local_open(utf8(tamper["token"]), key, footer, implicit) is not None)
    except Verdict as verdict:
        report.check("local tamper base opens", False, "verdict %s" % verdict.name)
    for case in tamper["cases"]:
        expect_verdict(report, "local tamper position %d" % case["position"], lambda: local_open(utf8(case["token"]), key, footer, implicit), "invalid")
    report.check("local tamper covers every position", sorted(c["position"] for c in tamper["cases"]) == list(range(len(tamper["token"]))))
    for weak in doc["weak-keys"]:
        expect_verdict(report, "weak key %s (%s)" % (weak["key"][:8], weak["reason"]), lambda: import_local_key(unhex(weak["key"])), weak["expect"])
    report.section("cb2_local.json", before)


def check_public_success(report, vector, mldsa):
    """Appendix A.2 success vector: PAE, Ed25519 half, verify, sign again."""
    name = vector["name"]
    pk = import_public_key(unhex(vector["public-key"]))
    sk = unhex(vector["secret-key"])
    footer, implicit = utf8(vector["footer"]), utf8(vector["implicit-assertion"])
    payload, token = utf8(vector["payload"]), utf8(vector["token"])
    try:
        import_secret_key(sk, mldsa)
    except Verdict as verdict:
        report.check("%s secret key import" % name, False, "verdict %s" % verdict.name)
        return
    report.check("%s public key matches secret key" % name, sk[32:64] + sk[64 + MLDSA_SECRET_BYTES :] == pk)
    signed = public_sign(sk, payload, footer, implicit, mldsa)
    if not report.check("%s pae" % name, signed["pae"] == unhex(vector["pae"]), "got %s" % signed["pae"].hex()):
        return
    report.check("%s ed25519 signature is deterministic" % name, signed["ed25519-signature"] == unhex(vector["ed25519-signature"]))
    body = split_token(token, PUBLIC_HEADER, footer)
    message, sig = body[:-SIGNATURE_BYTES], body[-SIGNATURE_BYTES:]
    report.check("%s body carries the recorded ed25519 half" % name, sig[:64] == unhex(vector["ed25519-signature"]))
    report.check("%s ed25519 half verifies over pae" % name, ed25519_verify(pk[:32], unhex(vector["pae"]), sig[:64]))
    report.check("%s token length formula" % name, len(token) == 11 + b64len(len(payload) + SIGNATURE_BYTES) + (1 + b64len(len(footer)) if footer else 0))
    try:
        opened, ml_checked = public_verify(token, pk, footer, implicit, mldsa)
    except Verdict as verdict:
        report.check("%s verify" % name, False, "verdict %s" % verdict.name)
        return
    report.check("%s verify" % name, opened == payload and message == payload)
    if not ml_checked:
        report.skip("%s ML-DSA-65 half" % name, "no ML-DSA-65 implementation")
    if signed["token"] is None:
        report.skip("%s sign again and verify" % name, "no ML-DSA-65 implementation")
        return
    try:
        again, _ = public_verify(signed["token"], pk, footer, implicit, mldsa)
        report.check("%s sign again and verify" % name, again == payload)
    except Verdict as verdict:
        report.check("%s sign again and verify" % name, False, "verdict %s" % verdict.name)


def expect_invalid_public(report, name, token, pk, footer, implicit, mldsa):
    """A public token that MUST be invalid, or skipped when only ML-DSA could tell."""
    try:
        _, ml_checked = public_verify(token, pk, footer, implicit, mldsa)
    except Verdict as verdict:
        report.check(name, verdict.name == "invalid", "verdict %s" % verdict.name)
        return
    if ml_checked:
        report.check(name, False, "accepted, expected invalid")
    else:
        report.skip(name, "Ed25519 half verifies; only the ML-DSA-65 half could refuse it")


def check_public(report, doc, mldsa):
    """Every member of cb2_public.json."""
    before = report.snapshot()
    for vector in doc["tests"]:
        name = vector["name"]
        if not vector["expect-fail"]:
            check_public_success(report, vector, mldsa)
            continue
        pk = unhex(vector["public-key"])
        footer, implicit = utf8(vector["footer"]), utf8(vector["implicit-assertion"])
        expect_invalid_public(report, "%s (%s)" % (name, vector["reason"]), utf8(vector["token"]), pk, footer, implicit, mldsa)
    tamper = doc["tamper"]
    pk = unhex(tamper["public-key"])
    footer, implicit = utf8(tamper["footer"]), utf8(tamper["implicit-assertion"])
    try:
        report.check("public tamper base verifies", public_verify(utf8(tamper["token"]), pk, footer, implicit, mldsa)[0] is not None)
    except Verdict as verdict:
        report.check("public tamper base verifies", False, "verdict %s" % verdict.name)
    for case in tamper["cases"]:
        expect_invalid_public(report, "public tamper position %d" % case["position"], utf8(case["token"]), pk, footer, implicit, mldsa)
    for rejected in doc["rejected-secret-keys"]:
        name = "%s (%s)" % (rejected["name"], rejected["reason"])
        sk = unhex(rejected["secret-key"])
        try:
            probed = import_secret_key(sk, mldsa)
        except Verdict as verdict:
            report.check(name, verdict.name == rejected["expect"], "verdict %s" % verdict.name)
            continue
        if probed:
            report.check(name, False, "accepted, expected %s" % rejected["expect"])
        else:
            report.skip(name, "the Ed25519 halves agree; only the ML-DSA-65 probe could refuse it")
    report.section("cb2_public.json", before)


def check_claims_vector(report, vector, mldsa):
    """Appendix A.3: reproduce a local token, then open under the rules."""
    name = vector["name"]
    payload, token = utf8(vector["payload"]), utf8(vector["token"])
    implicit = utf8(vector["implicit-assertion"])
    rules = Rules(vector["rules"])
    if vector["purpose"] == "local":
        key = import_local_key(unhex(vector["key"]))
        issuer_id = vector.get("key-id", kcb2_lid(key).decode("ascii"))
        sealed = local_seal(key, unhex(vector["nonce"]), payload, footer_for(issuer_id), implicit)
        if not report.check("%s reproduce" % name, sealed["token"] == token, "got %s" % sealed["token"].decode()):
            return
        verifier_id = vector.get("verifier-key-id", kcb2_lid(key).decode("ascii"))
        authenticate = lambda footer: local_open(token, key, footer, implicit)
    else:
        pk = import_public_key(unhex(vector["public-key"]))
        verifier_id = vector.get("verifier-key-id", kcb2_pid(pk).decode("ascii"))
        authenticate = lambda footer: public_verify(token, pk, footer, implicit, mldsa)[0]
    verdict, claims = open_claims(token, authenticate, verifier_id, rules)
    if not report.check("%s verdict" % name, verdict == vector["expect"], "got %s, expected %s" % (verdict, vector["expect"])):
        return
    if verdict == "ok":
        canonical = utf8(vector.get("payload-canonical", vector["payload"]))
        report.check("%s canonical text" % name, claims.to_json() == canonical, "got %s" % claims.to_json().decode("utf-8", "replace"))
    if vector["purpose"] == "public" and mldsa is None and verdict not in ("rules_incomplete", "too_large", "invalid"):
        report.skip("%s ML-DSA-65 half" % name, "no ML-DSA-65 implementation")


def check_claims(report, doc, mldsa):
    """Every vector of claims.json."""
    before = report.snapshot()
    for vector in doc["tests"]:
        check_claims_vector(report, vector, mldsa)
    report.section("claims.json", before)


def check_paserk(report, doc, mldsa):
    """Every key string of paserk.json, with the lengths of the section 7 table."""
    before = report.snapshot()
    local = doc["local"]
    key = import_local_key(unhex(local["key"]))
    report.check("kcb2.local", kcb2_local(key) == utf8(local["kcb2.local"]))
    report.check("kcb2.local length", len(kcb2_local(key)) == 54)
    report.check("kcb2.local round trip", parse_key_string(kcb2_local(key), b"kcb2.local.", 54) == key)
    report.check("kcb2.lid", kcb2_lid(key) == utf8(local["kcb2.lid"]))
    report.check("kcb2.lid length", len(kcb2_lid(key)) == 53)
    wrap = doc["local-wrap"]
    wrapping, wrapped_key = unhex(wrap["wrapping-key"]), unhex(wrap["key"])
    text = key_wrap(wrapping, wrapped_key, unhex(wrap["nonce"]))
    report.check("kcb2.local-wrap", text == utf8(wrap["kcb2.local-wrap"]), "got %s" % text.decode())
    report.check("kcb2.local-wrap length", len(text) == 144)
    try:
        report.check("kcb2.local-wrap unwraps", key_unwrap(utf8(wrap["kcb2.local-wrap"]), wrapping) == wrapped_key)
    except Verdict as verdict:
        report.check("kcb2.local-wrap unwraps", False, "verdict %s" % verdict.name)
    expect_verdict(report, "kcb2.local-wrap is not a cb2.local token", lambda: local_open(LOCAL_HEADER + text[len(WRAP_HEADER) :], wrapping, b"", b""), "invalid")
    public = doc["public"]
    pk, sk = import_public_key(unhex(public["public-key"])), unhex(public["secret-key"])
    report.check("kcb2.public", kcb2_public(pk) == utf8(public["kcb2.public"]))
    report.check("kcb2.public length", len(kcb2_public(pk)) == 2658)
    report.check("kcb2.pid", kcb2_pid(pk) == utf8(public["kcb2.pid"]))
    report.check("kcb2.pid length", len(kcb2_pid(pk)) == 53)
    report.check("kcb2.secret", kcb2_secret(sk) == utf8(public["kcb2.secret"]))
    report.check("kcb2.secret length", len(kcb2_secret(sk)) == 8076)
    report.check("kcb2.secret round trip", parse_key_string(utf8(public["kcb2.secret"]), b"kcb2.secret.", 8076) == sk)
    try:
        probed = import_secret_key(sk, mldsa)
        report.check("kcb2.secret imports", True)
        if not probed:
            report.skip("kcb2.secret ML-DSA-65 probe", "no ML-DSA-65 implementation")
    except Verdict as verdict:
        report.check("kcb2.secret imports", False, "verdict %s" % verdict.name)
    report.check("secret key carries its public key", sk[32:64] + sk[64 + MLDSA_SECRET_BYTES :] == pk)
    report.section("paserk.json", before)


def load(directory, filename):
    """Read one vector file."""
    with open(os.path.join(directory, filename), "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def main(argv):
    """Check every vector file and return the process exit status."""
    here = os.path.dirname(os.path.abspath(__file__))
    directory = argv[1] if len(argv) > 1 else os.path.join(os.path.dirname(here), "tests", "vectors")
    if SODIUM is None:
        print("XChaCha20 unavailable: pynacl's libsodium does not export crypto_core_hchacha20 and crypto_stream_chacha20_xor")
        return 2
    mldsa = load_mldsa()
    if mldsa is None:
        print("note: dilithium-py is not installed; the ML-DSA-65 half of cb2.public is not evaluated")
    report = Report()
    before = report.snapshot()
    check_decoder(report)
    report.section("decoder and primitives", before)
    check_local(report, load(directory, "cb2_local.json"))
    check_public(report, load(directory, "cb2_public.json"), mldsa)
    check_claims(report, load(directory, "claims.json"), mldsa)
    check_paserk(report, load(directory, "paserk.json"), mldsa)
    for note in report.notes:
        print(note)
    print("total: %d passed, %d failed, %d skipped" % (report.passed, report.failed, report.skipped))
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
