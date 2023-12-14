## Version NEXT

- Add `Crypto.JOSE.JWK.negotiateJWSAlg` which chooses the
  cryptographically strongest JWS algorithm for a given key,
  restricted to a given set of algorithms.  ([#118][])

- Added new conversion functions `Crypto.JOSE.JWK.fromX509PubKey`
  and `Crypto.JOSE.JWK.fromX509PrivKey`.  These convert from the
  `Data.X509.PubKey` and `Data.X509.PrivKey` types, which can be
  read via the *crypton-x509-store* package.  They supports RSA,
  NIST ECC, and Edwards curve key types (Ed25519, Ed448, X25519,
  X448).

- Updated `Crypto.JOSE.JWK.fromX509Certificate` to support Edwards
  curve key types (Ed25519, Ed448, X25519, X448).

- Added `Crypto.JOSE.JWK.fromRSAPublic :: RSA.PublicKey -> JWK`.


## Version 0.11 (2023-10-31)

- Migrate to the *crypton* library ecosystem.  *crypton* was a hard
  fork of *cryptonite*, which was no longer maintained.  With this
  change, the minimum supported version of GHC increased to 8.8.
  There are no other notable changes in this release.

- The `v0.10` series is the last release series to support
  *cryptonite*.  It will continue to receive important bug fixes
  until the end of 2024.


## Version 0.10 (2022-09-01)

- Introduce `newtype JOSE e m a` which behaves like `ExceptT e m a`
  but also has `instance (MonadRandom m) => MonadRandom (JOSE e m)`.
  The orphan `MonadRandom` instances were removed. ([#91][])

- Parameterise `JWT` over the claims data type.  This is a
  cleaner mechanism to support applications that use additional
  claims beyond those registered by RFC 7519.  `unregisteredClaims`
  and `addClaim` are deprecated and will be removed in a future
  release. ([#39][])

- Add Ed448 and X448 support. ([#74][])

- Add secp256k1 curve support (RFC 8812).

- Added `checkJWK :: (MonadError e m, AsError e) => JWK -> m ()`.
  This action performs some key usability checks.  In particular
  it identifies too-small symmetric keys.  ([#46][])

- Removed `QuickCheck` instances.  *jose* no longer depends on
  `QuickCheck`.  ([#106][])

- Removed orphan `ToJSON` and `FromJSON` instances for `URI`.

- Fail signature verification when curve does not match algorithm.
  This is an additional defence against curve substitution attacks.

- Improved error reporting when constructing a JWK from an X.509
  certificate with ECDSA key.

- Make compatible with `mtl == 2.3.*` ([#107][])

- Make compatible with `monad-time == 0.4`

[#39]: https://github.com/frasertweedale/hs-jose/issues/39
[#46]: https://github.com/frasertweedale/hs-jose/issues/46
[#74]: https://github.com/frasertweedale/hs-jose/issues/74
[#91]: https://github.com/frasertweedale/hs-jose/issues/91
[#106]: https://github.com/frasertweedale/hs-jose/issues/106
[#107]: https://github.com/frasertweedale/hs-jose/issues/107
[#118]: https://github.com/frasertweedale/hs-jose/issues/118


## Older versions

See Git commit history
