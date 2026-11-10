# I-314 — Post-quantum trust anchor (ML-DSA-65 attestation)

I-314 operates an **ML-DSA-65** key (the post-quantum signature algorithm standardized by NIST in FIPS 204) in
production and uses it to sign a live public attestation at `https://qlab.i-314.com/api/pqc/attest`. This repository
is the **out-of-band reference** for verifying it. Take the verifier and the fingerprints from here, never from the
website being verified: whoever serves a website can rewrite what it shows, but not this reference.

## Verify (recommended)

    python3 -I verify_attestation.py

Requires Python 3.8+ and OpenSSL 3.5+. The script fetches the live attestation and this repository's anchor files
over HTTPS only (it refuses redirects to plain HTTP), then checks, in order: the signature; the fingerprint of the key
that made it, computed from that key; the signed message (service, algorithm, key id and validity window); the anchor
(the root delegation when `ROOT.txt` exists, otherwise `FINGERPRINT.txt`); and `REVOKED.txt`. Exit codes: 0 verified,
1 not verified, 2 nothing concluded (network, tool or anchor error). Everything it prints that comes from the response
is escaped, so a response cannot draw fake lines on your terminal: trust the exit code. `--file att.json` verifies a
saved response and `--help` lists the options.

## What a pass proves, and what it does not

A pass proves that the attestation was signed by a key that I-314 anchors here. It does **not** authenticate your
session or the website you are on: a genuine attestation can be copied or relayed by a third party. Use it for
independent technical verification (for example, due diligence), not as a site-security indicator.

## Anchor files

| File | Content |
|---|---|
| `FINGERPRINT.txt` | SHA-256 fingerprint of the current online signing key |
| `ROOT.txt` | When present: fingerprint of the root key that certifies online keys. From then on the root is the trust anchor, and an attestation without a valid delegation from it fails |
| `REVOKED.txt` | Key ids (`mldsa65-<16 hex>`) or fingerprints that must no longer be trusted, one per line, with `#` comments. The file is required, and any entry the verifier does not recognize makes verification fail closed |

**What exactly is hashed:** the raw ML-DSA-65 public key (1952 bytes), which is the last 1952 bytes of its DER
SubjectPublicKeyInfo. For the current key, hashing the whole DER SPKI instead gives
`dea911da01d999d966588ddf704443f932de8386a35eae9156529cda8bc53398`; that value is listed only for tools that
fingerprint the full SPKI.

Current online key: `3474f51e5400d12a105cd991796c822833aff02bc47bd16bb9f1c1e62017444b`
(key id `mldsa65-3474f51e5400d12a`).

## Manual check (without the script)

    curl -fsS https://qlab.i-314.com/api/pqc/attest > att.json

    # 1) the ML-DSA-65 signature is valid for the key in the response:
    jq -rj .message att.json > m.txt
    jq -r .signature_b64 att.json | base64 -d > s.bin
    jq -r .public_key_pem att.json > pub.pem
    openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in m.txt -sigfile s.bin
    # -> Signature Verified Successfully
    #    This alone proves cryptographic consistency, not identity: anyone can sign
    #    their own message with their own key and pass this step.

    # 2) the key that verified the signature is the anchored key:
    openssl pkey -pubin -in pub.pem -outform DER | tail -c 1952 | openssl dgst -sha256
    # -> must equal the fingerprint in FINGERPRINT.txt. Compute it from pub.pem, the key
    #    used in step 1, never from another field of att.json: a forged response could
    #    pair an attacker's signing key with I-314's raw key in a separate field.

The manual check only covers the signature and the key. It does not check the message's service, format or validity
window, nor the root delegation or revocation. The script does.

## Keys and their uses

- The online key signs the attestation message
  `i314-pqc-attestation-v2|service=…|alg=ML-DSA-65|key_id=…|issued_at=…|expires_at=…`, re-signed every ~15 s.
  `expires_at` is a validity rule for verifiers, not replay protection.
- The same key also signs Q-LAB's ML-KEM-768 channel key, as `i314-pqc-channel-ek-v1|<key>`. The distinct prefixes
  keep the two uses from being confused, and the server never signs content supplied by a visitor.
- When `ROOT.txt` is published, the root key signs only delegations,
  `i314-pqc-delegation-v1|root_key_id=…|key_id=…|alg=…|key_sha256=…|purposes=…|not_before=…|not_after=…`, which the
  server publishes with each attestation. The root key never resides on the server: it is kept encrypted, under the
  custody of I-314's founder.

## Rotation and revocation

- An online key is rotated by generating a new one, certifying it with a new delegation from the root, updating
  `FINGERPRINT.txt` and adding the previous key id to `REVOKED.txt`. The new key is activated only once its delegation
  is installed, and the previous private key is not kept.
- A compromised online key is added to `REVOKED.txt`; verifiers reject it even while its delegation is valid.
- Once `ROOT.txt` exists, delegations last at most 180 days, so a key that is not re-certified stops verifying on its
  own.
- A compromised root would be announced here, with a new `ROOT.txt` and the old root in `REVOKED.txt`.

## Changes

- 2026-11-09 (b): reference verifier (HTTPS only, escaped output, strict anchor files that fail closed); message v2
  with key id and expiry; anchor files for a root key and revocation; the key's second use documented. The
  fingerprint did not change.
- 2026-11-09: step 2 now hashes the same key that verified the signature. The previous step 2 hashed the
  `public_key_raw_b64` field, which a forged response could fill with I-314's key while signing with a different key.
- 2026-11-02: first publication.

Algorithm: ML-DSA-65 (NIST FIPS 204). Last updated: 2026-11-09.
