# jose - Javascript Object Signing and Encryption & JWT (JSON Web Token)

jose is a Haskell implementation of [Javascript Object Signing and
Encryption](https://datatracker.ietf.org/wg/jose/) and [JSON Web
Token](https://tools.ietf.org/html/rfc7519).

The JSON Web Signature (JWS; RFC 7515) implementation is complete.
JSON Web Encryption (JWE; RFC 7516) is not yet implemented.

**EdDSA** signatures (RFC 8037) are supported (Ed25519 only).

The **ECDSA implementation is vulnerable to timing attacks** and
should therefore only be used for verification.

JWK Thumbprint (RFC 7638) is supported (requires *aeson* >= 0.10).

Contributions are welcome.
