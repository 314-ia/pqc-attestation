# I-314 — Ancla de confianza post-cuántica (atestación ML-DSA-65)

I-314 opera una clave **ML-DSA-65** (FIPS 204) en producción y firma con ella una
atestación pública en vivo. Esta página es la **referencia fuera de banda** para
verificar esa clave.

## Huella canónica de la clave pública (SHA-256)

    3474f51e5400d12a105cd991796c822833aff02bc47bd16bb9f1c1e62017444b

Comprobá que esta huella coincida con la que muestra **qlab.i-314.com** en la pantalla
de ingreso. Si coinciden, estás viendo la clave real de I-314. Se publica acá, en un
canal independiente del sitio, a propósito: quien sirve el sitio podría reescribir lo
que muestra, pero no esta referencia.

## Verificación técnica (auditores)

La atestación pública (JSON firmado, re-firmado cada ~15 s) está en
`https://qlab.i-314.com/api/pqc/attest`. Con `jq` y OpenSSL 3.5+:

    curl -s https://qlab.i-314.com/api/pqc/attest > att.json

    # 1) la firma ML-DSA-65 es válida:
    jq -rj .message att.json > m.txt
    jq -r .signature_b64 att.json | base64 -d > s.bin
    jq -r .public_key_pem att.json > pub.pem
    openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in m.txt -sigfile s.bin
    # -> Signature Verified Successfully

    # 2) la clave pública es la de esta página:
    jq -r .public_key_raw_b64 att.json | base64 -d | sha256sum
    # -> debe empezar con 3474f51e5400d12a... (la huella de arriba)

Algoritmo: ML-DSA-65 (FIPS 204). Actualizado: 2026-11-02.
