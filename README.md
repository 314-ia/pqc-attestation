# I-314 — Post-quantum trust anchor (ML-DSA-65 attestation)

I-314 operates an **ML-DSA-65** (FIPS 204) key in production and uses it to sign a live
public attestation. This page is the **out-of-band reference** for verifying that key.

## Canonical public-key fingerprint (SHA-256)

    3474f51e5400d12a105cd991796c822833aff02bc47bd16bb9f1c1e62017444b

**What exactly is hashed:** the raw ML-DSA-65 public key (1952 bytes), which is the last
1952 bytes of its DER SubjectPublicKeyInfo. Hashing the whole DER SPKI of the same key gives
`dea911da01d999d966588ddf704443f932de8386a35eae9156529cda8bc53398`; that value is listed only
for tools that fingerprint the full SPKI. The canonical value is the one above.

**Compare it with the fingerprint you compute yourself** from the key that verified the
attestation's signature (step 2 below). A fingerprint that a website merely displays proves
nothing: any site, including a cloned one, can display this string. This reference is
published here, on a channel independent of the site, on purpose: whoever serves the site
could rewrite what it shows, but not this reference.

**What a match proves, and what it does not:** a match proves that the attestation was
signed by I-314's key. It does **not** authenticate your session or the page you are on: a
genuine attestation can be copied or relayed by a third party. Use it for independent
technical verification (for example, due diligence), not as a site-security indicator.

## Technical verification (auditors)

The public attestation (signed JSON, re-signed every ~15 s) is served at
`https://qlab.i-314.com/api/pqc/attest`. With `jq` and OpenSSL 3.5+:

    curl -fsS https://qlab.i-314.com/api/pqc/attest > att.json

    # 1) the ML-DSA-65 signature is valid for the key in the response:
    jq -rj .message att.json > m.txt
    jq -r .signature_b64 att.json | base64 -d > s.bin
    jq -r .public_key_pem att.json > pub.pem
    openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in m.txt -sigfile s.bin
    # -> Signature Verified Successfully
    #    This alone proves cryptographic consistency, not identity: anyone can sign
    #    their own message with their own key and pass this step.

    # 2) the key that verified the signature is I-314's key:
    openssl pkey -pubin -in pub.pem -outform DER | tail -c 1952 | openssl dgst -sha256
    # -> must equal 3474f51e5400d12a105cd991796c822833aff02bc47bd16bb9f1c1e62017444b
    #    Compute it from pub.pem, the key used in step 1, never from another field of
    #    att.json: a forged response could pair an attacker's signing key with I-314's
    #    raw key in a separate field.

## Changes

- 2026-11-09: step 2 now hashes the same key that verified the signature. The previous
  step 2 hashed the `public_key_raw_b64` field, which a forged response could fill with
  I-314's key while signing with a different key. The fingerprint itself did not change.
- 2026-11-02: first publication.

Algorithm: ML-DSA-65 (FIPS 204). Last updated: 2026-11-09.
