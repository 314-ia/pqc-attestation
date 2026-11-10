#!/usr/bin/env python3
"""Reference verifier for I-314's post-quantum attestation (ML-DSA-65, NIST FIPS 204).

Published at https://github.com/314-ia/pqc-attestation. Get this script from there, not from the website being
verified: a copy served by that website is only as trustworthy as the website.

What it checks, in order:
  1. The attestation's signature is a valid ML-DSA-65 signature over its message, with the key in the response.
  2. The fingerprint of THAT key (SHA-256 of the raw 1952-byte public key), computed here, never read from a field.
  3. The signed message: format, service, algorithm, key identifier bound to that key, and validity window.
  4. The trust anchor, fetched from the GitHub repository (or a local copy):
       - if the anchor declares a root key (ROOT.txt), the attestation must carry a delegation signed by that root,
         binding this exact key, currently valid, for the "attestation" purpose;
       - otherwise the key fingerprint must equal the one in FINGERPRINT.txt.
  5. Neither the key nor the root is listed in REVOKED.txt (required; any unrecognized entry fails closed).

A pass proves the message was signed by a key that I-314 anchors. It does NOT authenticate your session or the
website you are on: a genuine attestation can be copied or relayed by a third party.

Everything printed that comes from the verified party is escaped, so a response cannot draw fake lines on your
terminal. Only the exit code and the final line written by this script count.

Usage:
  python3 -I verify_attestation.py                         # live attestation + anchor from GitHub
  python3 -I verify_attestation.py --file att.json         # a saved response
  python3 -I verify_attestation.py --anchor ./pqc-attestation   # anchor files from a local directory
Options: --url URL  --service HOST  --openssl PATH  --now ISO8601  --skew SECONDS  --allow-v1  --quiet  --warn-exit
Exit codes: 0 verified · 1 not verified · 2 usage, network or tool error (nothing concluded) ·
            3 verified with warnings (only with --warn-exit, e.g. a delegation about to expire).
Requirements: Python 3.8+ (standard library only) and OpenSSL 3.5+ with ML-DSA.
"""
import argparse
import base64
import datetime
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

DEFAULT_URL = "https://qlab.i-314.com/api/pqc/attest"
DEFAULT_ANCHOR = "https://raw.githubusercontent.com/314-ia/pqc-attestation/main/"
DEFAULT_SERVICE = "qlab.i-314.com"
ALG = "ML-DSA-65"
RAW_LEN = 1952
# DER SubjectPublicKeyInfo header of every ML-DSA-65 public key (OID 2.16.840.1.101.3.4.3.18), then the raw key.
SPKI_HEADER = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
ATT_V2, ATT_V1, DELEG_V1 = "i314-pqc-attestation-v2", "i314-pqc-attestation-v1", "i314-pqc-delegation-v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^mldsa65-[0-9a-f]{16}$")
PEM_PUBLIC = re.compile(r"\A\s*-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*\Z")
MAX_BYTES = 1 << 20
TOTAL_TIMEOUT_S = 30           # whole download, not per read: a server that trickles bytes cannot hold us
MAX_VALIDITY_S = 3600          # sanity bound on expires_at - issued_at
MAX_DELEGATION_DAYS = 180      # published policy: a delegation lasts at most 180 days
WARN_DAYS = 21                 # warn when a delegation is about to expire
V1_MAX_AGE_S = 120             # legacy v1 messages carry no expiry: accept only very recent ones (with --allow-v1)
EXIT_OK, EXIT_FAIL, EXIT_ERROR, EXIT_WARN = 0, 1, 2, 3


class Fail(Exception):
    """The attestation does not verify."""


class Usage(Exception):
    """Usage, network or tool problem: nothing was concluded about the attestation."""


def show(value, limit=600):
    """Printable form of any text that may come from the verified party: control, format, surrogate and other
    non-printable characters are escaped, so a response cannot draw fake lines or hide text on the terminal."""
    s = value if isinstance(value, str) else str(value)
    out = []
    for ch in s[:limit]:
        if ch.isprintable():
            out.append(ch)
        else:
            cp = ord(ch)
            out.append(f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}" if cp < 0x10000 else f"\\U{cp:08x}")
    if len(s) > limit:
        out.append("…")
    return "".join(out)


def emit(line, err=False):
    print(show(line, limit=2000), file=sys.stderr if err else sys.stdout)


def key_id_for(fp):
    return "mldsa65-" + fp[:16]


def parse_time(s, what):
    try:
        t = datetime.datetime.fromisoformat(s)
    except (TypeError, ValueError):
        raise Fail(f"{what}: not an ISO-8601 timestamp: {s!r}")
    if t.tzinfo is None:
        raise Fail(f"{what}: timestamp without time zone: {s!r}")
    return t


class _HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise Usage(f"refusing a redirect to a non-HTTPS URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HTTPSOnlyRedirect)


def fetch(url, allow_404=False):
    if not url.startswith("https://"):
        raise Usage(f"refusing a non-HTTPS URL: {url}")
    deadline = time.monotonic() + TOTAL_TIMEOUT_S
    req = urllib.request.Request(url, headers={"User-Agent": "i314-attestation-verifier/2", "Accept": "*/*"})
    try:
        with _OPENER.open(req, timeout=20) as r:
            if getattr(r, "status", None) != 200:
                raise Usage(f"HTTP {getattr(r, 'status', '?')} fetching {url} (expected 200)")
            chunks, n = [], 0
            reader = getattr(r, "read1", None) or r.read
            while True:
                if time.monotonic() > deadline:
                    raise Usage(f"timed out fetching {url}")
                c = reader(65536)
                if not c:
                    break
                n += len(c)
                if n > MAX_BYTES:
                    raise Usage(f"response too large: {url}")
                chunks.append(c)
    except urllib.error.HTTPError as e:
        if allow_404 and e.code == 404:
            return None
        raise Usage(f"HTTP {e.code} fetching {url}")
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise Usage(f"cannot fetch {url}: {e}")
    return b"".join(chunks)


def read_anchor_file(anchor, name, required):
    if anchor.startswith(("https://", "http://")):
        data = fetch(anchor.rstrip("/") + "/" + name, allow_404=not required)
        if data is None and required:
            raise Usage(f"anchor file missing: {name}")
    else:
        path = os.path.join(anchor, name)
        if not os.path.exists(path):
            if required:
                raise Usage(f"anchor file missing: {path}")
            return None
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_BYTES + 1)
        except OSError as e:
            raise Usage(f"cannot read {path}: {e}")
    if data is None:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise Usage(f"{name} is not valid UTF-8")


def parse_anchor(text, name, allow_key_ids):
    """Strict parser: one entry per non-comment token; anything that is not a fingerprint (or a key id, where allowed)
    is an error, so a hand-edited typo fails closed instead of being silently ignored."""
    entries = []
    for n, line in enumerate(text.splitlines(), 1):
        for tok in line.split("#", 1)[0].split():
            t = tok.lower()
            if HEX64.match(t) or (allow_key_ids and KEY_ID.match(t)):
                entries.append(t)
            else:
                kind = "a SHA-256 fingerprint or a key id" if allow_key_ids else "a SHA-256 fingerprint"
                raise Usage(f"{name} line {n}: unrecognized entry {tok!r} (expected {kind})")
    return entries


def load_anchor(anchor):
    fps = parse_anchor(read_anchor_file(anchor, "FINGERPRINT.txt", True), "FINGERPRINT.txt", False)
    if len(fps) != 1:
        raise Usage("FINGERPRINT.txt must contain exactly one SHA-256 fingerprint")
    root_text = read_anchor_file(anchor, "ROOT.txt", False)
    roots = parse_anchor(root_text, "ROOT.txt", False) if root_text is not None else []
    if root_text is not None and len(roots) != 1:
        raise Usage("ROOT.txt must contain exactly one SHA-256 fingerprint")
    revoked = set(parse_anchor(read_anchor_file(anchor, "REVOKED.txt", True), "REVOKED.txt", True))
    return {"key_fp": fps[0], "root_fp": roots[0] if roots else None, "revoked": revoked}


class OpenSSL:
    def __init__(self, path, workdir):
        self.path, self.dir, self.n = path, workdir, 0

    def run(self, args):
        try:
            return subprocess.run([self.path, *args], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            raise Usage(f"openssl not found: {self.path}")
        except subprocess.TimeoutExpired:
            raise Usage("openssl timed out")

    def check_mldsa(self):
        r = self.run(["list", "-signature-algorithms"])
        if r.returncode != 0 or b"ML-DSA-65" not in r.stdout:
            raise Usage("this OpenSSL has no ML-DSA-65 (OpenSSL 3.5 or newer is required)")

    def _file(self, data, suffix):
        self.n += 1
        p = os.path.join(self.dir, f"f{self.n}{suffix}")
        with open(p, "wb") as f:
            f.write(data)
        return p

    def _pem(self, pem_text, what):
        if not isinstance(pem_text, str) or not PEM_PUBLIC.match(pem_text):
            raise Fail(f"{what} is not exactly one PEM public key")
        return self._file(pem_text.encode("ascii"), ".pem")

    def raw_fingerprint(self, pem_text, what):
        """SHA-256 of the raw ML-DSA-65 key inside this PEM; fails unless it is exactly an ML-DSA-65 public key."""
        r = self.run(["pkey", "-pubin", "-in", self._pem(pem_text, what), "-outform", "DER"])
        der = r.stdout
        if r.returncode != 0 or len(der) != len(SPKI_HEADER) + RAW_LEN or not der.startswith(SPKI_HEADER):
            raise Fail(f"{what} is not an ML-DSA-65 public key")
        return hashlib.sha256(der[len(SPKI_HEADER):]).hexdigest()

    def verify(self, pem_text, message, sig, what="key"):
        r = self.run(["pkeyutl", "-verify", "-pubin", "-inkey", self._pem(pem_text, what), "-rawin",
                      "-in", self._file(message, ".msg"), "-sigfile", self._file(sig, ".sig")])
        return r.returncode == 0


def fields(message, prefix, keys):
    parts = message.split("|")
    if parts[0] != prefix:
        raise Fail(f"unexpected message prefix: {parts[0]!r}")
    out = {}
    for p in parts[1:]:
        k, sep, v = p.partition("=")
        if not sep or k in out:
            raise Fail(f"malformed message field: {p!r}")
        out[k] = v
    if set(out) != set(keys):
        raise Fail(f"message fields {sorted(out)} != expected {sorted(keys)}")
    return out


def b64(s, what):
    try:
        return base64.b64decode(s, validate=True)
    except (TypeError, ValueError):
        raise Fail(f"{what}: invalid base64")


def check_delegation(ossl, deleg, key_fp, key_id, root_fp_anchor, now, skew, say, warn=None):
    if not isinstance(deleg, dict):
        raise Fail("the anchor declares a root key, but the attestation carries no delegation (possible downgrade)")
    for k in ("message", "signature_b64", "root_public_key_pem"):
        if not isinstance(deleg.get(k), str) or not deleg[k]:
            raise Fail(f"delegation: missing {k}")
    root_fp = ossl.raw_fingerprint(deleg["root_public_key_pem"], "delegation root key")
    if root_fp != root_fp_anchor:
        raise Fail(f"delegation root key {root_fp[:16]}… is not the anchored root {root_fp_anchor[:16]}…")
    if root_fp == key_fp:
        raise Fail("the root key and the online key are the same key (self-delegation)")
    if not ossl.verify(deleg["root_public_key_pem"], deleg["message"].encode(), b64(deleg["signature_b64"],
                                                                                    "delegation signature"),
                       "delegation root key"):
        raise Fail("delegation signature does not verify with the anchored root key")
    d = fields(deleg["message"], DELEG_V1,
               ("root_key_id", "key_id", "alg", "key_sha256", "purposes", "not_before", "not_after"))
    if d["root_key_id"] != key_id_for(root_fp) or d["alg"] != ALG:
        raise Fail("delegation names another root or algorithm")
    if d["key_sha256"] != key_fp or d["key_id"] != key_id:
        raise Fail("delegation certifies a different key than the one that signed the attestation")
    if "attestation" not in d["purposes"].split(","):
        raise Fail("delegation does not cover the 'attestation' purpose")
    nb, na = parse_time(d["not_before"], "delegation not_before"), parse_time(d["not_after"], "delegation not_after")
    if not nb < na:
        raise Fail("delegation validity window is empty or inverted")
    if na - nb > datetime.timedelta(days=MAX_DELEGATION_DAYS, minutes=5):
        raise Fail(f"delegation lasts longer than the published policy ({MAX_DELEGATION_DAYS} days)")
    if not (nb - skew <= now <= na + skew):
        raise Fail(f"delegation is not valid now (valid {d['not_before']} .. {d['not_after']})")
    say("ok", f"delegation: anchored root {root_fp[:16]}… certifies key {key_id} until {d['not_after']}")
    left = na - now
    if left < datetime.timedelta(days=WARN_DAYS) and warn is not None:
        warn(f"the delegation expires in {max(left.days, 0)} days ({d['not_after']}): it must be renewed")
    return root_fp


def run(args):
    say = (lambda tag, msg: None) if args.quiet else (lambda tag, msg: emit(f"[{tag}] {msg}"))
    warnings = []

    def warn(msg):
        warnings.append(msg)
        emit(f"[warn] {msg}")

    try:
        now = parse_time(args.now, "--now") if args.now else datetime.datetime.now(datetime.timezone.utc)
    except Fail as e:
        emit(f"ERROR: {e}", err=True)
        return EXIT_ERROR
    if args.skew < 0 or args.skew > 3600:
        emit("ERROR: --skew must be between 0 and 3600 seconds", err=True)
        return EXIT_ERROR
    skew = datetime.timedelta(seconds=args.skew)
    tmp = tempfile.mkdtemp(prefix="i314-verify-")
    try:
        ossl = OpenSSL(args.openssl, tmp)
        ossl.check_mldsa()
        if args.file:
            try:
                with open(args.file, "rb") as f:
                    raw = f.read(MAX_BYTES + 1)
            except OSError as e:
                raise Usage(f"cannot read {args.file}: {e}")
            src = args.file
        else:
            raw, src = fetch(args.url), args.url
        try:
            att = json.loads(raw)
        except (ValueError, RecursionError):
            raise Fail(f"the attestation from {src} is not valid JSON")
        if not isinstance(att, dict) or att.get("error"):
            raise Fail(f"no attestation from {src}: {att.get('error') if isinstance(att, dict) else 'not an object'}")
        for k in ("message", "signature_b64", "public_key_pem"):
            if not isinstance(att.get(k), str) or not att[k]:
                raise Fail(f"attestation: missing {k}")
        say("ok", f"attestation read from {src}")

        # 1-2. signature with the key in the response; fingerprint computed from THAT key
        if not ossl.verify(att["public_key_pem"], att["message"].encode(), b64(att["signature_b64"], "signature"),
                           "attestation key"):
            raise Fail("the signature does not verify with the key in the response")
        fp = ossl.raw_fingerprint(att["public_key_pem"], "attestation key")
        kid = key_id_for(fp)
        say("ok", f"signature: valid {ALG} signature by the key in the response (fingerprint {fp})")

        # 3. the signed message
        if att["message"].startswith(ATT_V2 + "|"):
            m = fields(att["message"], ATT_V2, ("service", "alg", "key_id", "issued_at", "expires_at"))
            if m["key_id"] != kid:
                raise Fail(f"message key_id {m['key_id']!r} does not match the signing key ({kid})")
            ia, ea = parse_time(m["issued_at"], "issued_at"), parse_time(m["expires_at"], "expires_at")
            if not (datetime.timedelta(0) < ea - ia <= datetime.timedelta(seconds=MAX_VALIDITY_S)):
                raise Fail("implausible validity window in the message")
            if not (ia - skew <= now <= ea + skew):
                raise Fail(f"attestation not valid now (issued {m['issued_at']}, expires {m['expires_at']})")
        elif att["message"].startswith(ATT_V1 + "|") and args.allow_v1:
            m = fields(att["message"], ATT_V1, ("service", "alg", "issued_at"))
            ia = parse_time(m["issued_at"], "issued_at")
            if not (ia - skew <= now <= ia + datetime.timedelta(seconds=V1_MAX_AGE_S) + skew):
                raise Fail(f"legacy v1 attestation is not recent (issued {m['issued_at']})")
            warn("legacy v1 message: no key identifier and no expiry")
        else:
            raise Fail("unknown or legacy message format (use --allow-v1 only for old evidence)")
        if m["alg"] != ALG:
            raise Fail(f"message algorithm {m['alg']!r} is not {ALG}")
        if m["service"] != args.service:
            raise Fail(f"message service {m['service']!r} is not {args.service!r}")
        say("ok", f"message: service={m['service']}, alg={m['alg']}, valid now")

        # 4. trust anchor
        anchor = load_anchor(args.anchor)
        if anchor["root_fp"]:
            root_fp = check_delegation(ossl, att.get("delegation"), fp, kid, anchor["root_fp"], now, skew, say, warn)
        else:
            root_fp = None
            if fp != anchor["key_fp"]:
                raise Fail(f"key fingerprint {fp[:16]}… is not the anchored one {anchor['key_fp'][:16]}…")
            say("ok", "anchor: the key fingerprint matches FINGERPRINT.txt")
            if att.get("delegation"):
                say("note", "the response carries a delegation, but the anchor declares no root key: ignored")

        # 5. revocation
        if {fp, kid} & anchor["revoked"] or (root_fp and {root_fp, key_id_for(root_fp)} & anchor["revoked"]):
            raise Fail("the key (or its root) is listed in REVOKED.txt")
        say("ok", "not revoked")
        when = f" (evaluated at {args.now}, not at the current time)" if args.now else ""
        tail = " WITH WARNINGS (see [warn] above)" if warnings else ""
        emit(f"VERIFIED{tail}: signed by I-314's anchored {ALG} key {kid}{when}. This does NOT authenticate your "
             "session or the website you are on: a genuine attestation can be copied or relayed.")
        return EXIT_WARN if (warnings and args.warn_exit) else EXIT_OK
    except Fail as e:
        emit(f"NOT VERIFIED: {e}")
        return EXIT_FAIL
    except UnicodeError:
        emit("NOT VERIFIED: the attestation contains invalid characters")
        return EXIT_FAIL
    except Usage as e:
        emit(f"ERROR: {e}", err=True)
        return EXIT_ERROR
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify I-314's ML-DSA-65 attestation against its published anchor.")
    ap.add_argument("--url", default=DEFAULT_URL, help="attestation endpoint (HTTPS)")
    ap.add_argument("--file", help="verify a saved attestation JSON instead of fetching it")
    ap.add_argument("--anchor", default=DEFAULT_ANCHOR, help="anchor base URL (HTTPS) or local directory")
    ap.add_argument("--service", default=DEFAULT_SERVICE, help="expected service name in the signed message")
    ap.add_argument("--openssl", default=os.environ.get("OPENSSL", "openssl"), help="OpenSSL 3.5+ binary")
    ap.add_argument("--now", help="evaluate validity at this ISO-8601 time instead of the current time")
    ap.add_argument("--skew", type=int, default=60, help="allowed clock skew in seconds (default 60)")
    ap.add_argument("--allow-v1", action="store_true", help="accept the legacy v1 message format (old evidence)")
    ap.add_argument("--quiet", action="store_true", help="print only warnings and the final result")
    ap.add_argument("--warn-exit", action="store_true", help="exit 3 instead of 0 when verified with warnings")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
