# I-314 — Post-quantum trust anchor (ML-DSA-65 attestation)

I-314 operates an **ML-DSA-65** (FIPS 204) key in production and uses it to sign a live
public attestation. This page is the **out-of-band reference** for verifying that key.

## Canonical public-key fingerprint (SHA-256)

    3474f51e5400d12a105cd991796c822833aff02bc47bd16bb9f1c1e62017444b

Check that this fingerprint matches the one shown by **qlab.i-314.com** on its sign-in
screen. If they match, you are seeing I-314's real key. It is published here, on a
channel independent of the site, on purpose: whoever serves the site could rewrite what
it shows, but not this reference.

## Technical verification (auditors)

The public attestation (signed JSON, re-signed every ~15 s) is served at
`https://qlab.i-314.com/api/pqc/attest`. With `jq` and OpenSSL 3.5+:

    curl -s https://qlab.i-314.com/api/pqc/attest > att.json

    # 1) the ML-DSA-65 signature is valid:
    jq -rj .message att.json > m.txt
    jq -r .signature_b64 att.json | base64 -d > s.bin
    jq -r .public_key_pem att.json > pub.pem
    openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in m.txt -sigfile s.bin
    # -> Signature Verified Successfully

    # 2) the public key is the one on this page:
    jq -r .public_key_raw_b64 att.json | base64 -d | sha256sum
    # -> must start with 3474f51e5400d12a... (the fingerprint above)

Algorithm: ML-DSA-65 (FIPS 204). Last updated: 2026-11-02.
