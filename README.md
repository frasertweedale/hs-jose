# jose - Javascript Object Signing and Encryption & JWT (JSON Web Token)

*jose* is a Haskell implementation of [Javascript Object Signing and
Encryption](https://datatracker.ietf.org/wg/jose/) and [JSON Web
Token](https://tools.ietf.org/html/rfc7519).

The JSON Web Signature (JWS; RFC 7515) implementation is complete.
JSON Web Encryption (JWE; RFC 7516) is not yet implemented.

**EdDSA** signatures (RFC 8037) are supported (Ed25519 only).

JWK Thumbprint (RFC 7638) is supported (requires *aeson* >= 0.10).

[Contributions](#contributing) are welcome.

## Security

If you discover a security issue in this library, please email me
the details, ideally with a proof of concept (`frase @ frase.id.au`
; [PGP key](https://pgp.mit.edu/pks/lookup?op=get&search=0x4B5390524111E1E2)).

Before reporting an issue, please not the following known
vulnerabilities:

- The **ECDSA** implementation is vulnerable to **timing attacks** and
  should therefore only be used for verification.

and the following known **not-vulnerabilities**:

- The library is not vulnerable to [JWS **algorithm substitution
  attacks**](
  https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/).
  Haskell's type system excludes this attack.

- The default JWS validation settings reject the **`"none"`
  algorithm**, as [required by RFC 7518](
  https://tools.ietf.org/html/rfc7518#section-3.6).

- The library is not vulnerable to ECDH [**invalid curve attacks**](
  https://blogs.adobe.com/security/2017/03/critical-vulnerability-uncovered-in-json-encryption.html)
  because JWE is not implemented.


## Interoperability issues

The following known interoperability issues will not be addressed,
so please do not open issues:

- Some JOSE tools and libraries permit the use of **short keys**, in
  violation of the RFCs.  This implementation reject JWS or JWT
  objects minted with short keys, as required by the RFCs.

- The *Auth0* software produces objects with an [invalid `"x5t"`
  parameter](
  https://community.auth0.com/questions/7227/certificate-thumbprint-is-longer-than-20-bytes).
  The datum [should be a base64url-encoded SHA-1 digest](
  https://tools.ietf.org/html/rfc7515#section-4.1.7), but *Auth0*
  produces a base64url-encoded hex-encoded SHA-1 digest.  The object
  can be repaired so that this library will admit it, unless the
  offending parameter is part of the *JWS Protected Header* in which
  case you are out of luck until *Auth0* bring their implementation
  into compliance.


## Contributing

Bug reports, patches, feature requests, code review, crypto review,
examples and documentation are welcome.

If you are wondering about how or whether to implement some feature
or fix, please open an issue where it can be discussed.  I
appreciate your efforts, but I do not wish such efforts to be
misplaced.

To submit a patch, please use ``git send-email`` or open a pull
request.  Write a [well formed commit message](
http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).
If your patch is nontrivial, update the copyright notice at the top
of the modified files
