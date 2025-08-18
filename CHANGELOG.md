## Version NEXT

- GHC 9.6 is now the earliest supported version.

- Changed the header protection data types for better ergonomics
  ([#125](https://github.com/frasertweedale/hs-jose/issues/125)).
  Previously, `()` was used for serialisations that only support
  protected headers (thus, a single constructor).  This release
  introduces the new singleton data type `RequiredProtected` to
  replace the use of `()` for this purpose.  This is a breaking
  change and some library users will need to update their code.

  The `Protection` type has been renamed to `OptionalProtection`,
  with the old name retained as a (deprecated) type synonym.

  The `ProtectionIndicator` class has been renamed to
  `ProtectionSupport`, with the old name retained as a (deprecated)
  type synonym.

  Added some convenience header and header parameter constructors:
  `newJWSHeaderProtected`, `newHeaderParamProtected` and
  `newHeaderParamUnprotected`.

- Generalised the types of `signJWT`, `verifyJWT` and related
  functions to accept custom JWS header types.  Added new type
  synonym `SignedJWTWithHeader h`.  This change could break some
  applications by introducing ambiguity.  The solution is to use
  a type annotation, type application, or explicit coercion
  function, as in the below examples:

  ```haskell
  -- type application
  {-# LANGUAGE TypeApplications #-}
  decodeCompact @SignedJWT s >>= verifyClaims settings k

  -- type annotation
  do
    jwt <- decodeCompact s
    verifyClaims settings k (jwt :: SignedJWT)

  -- coercion function
  let
    fixType = id :: SignedJWT -> SignedJWT
  in
    verifyClaims settings k . fixType =<< decodeCompact s
  ```

- Added `unsafeGetPayload`, `unsafeGetJWTPayload` and
  `unsafeGetJWTClaimsSet` functions.  These enable access to
  the JWS/JWT payload without cryptographic verification.  As
  the name implies, these should be used with the utmost caution!
  ([#126](https://github.com/frasertweedale/hs-jose/issues/126))

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

- Added `Ord` instance for `StringOrURI` ([#134]; contributed by
  Chris Penner).

- Added `Semigroup` and `Monoid` instances for `JWKSet`
  ([#135]; contributed by Torgeir Strand Henriksen).

[#134]: https://github.com/frasertweedale/hs-jose/pull/134
[#135]: https://github.com/frasertweedale/hs-jose/pull/135


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
[#122]: https://github.com/frasertweedale/hs-jose/issues/122


## Older versions

See Git commit history
