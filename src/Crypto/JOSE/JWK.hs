-- Copyright (C) 2013-2023  Fraser Tweedale
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}

{-|

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
structure that represents a cryptographic key.  This module also
defines a JSON Web Key Set (JWK Set) JSON data structure for
representing a set of JWKs.

@
-- Generate RSA JWK and set "kid" param to
-- base64url-encoded SHA-256 thumbprint of key.
--
doGen :: IO JWK
doGen = do
  jwk <- 'genJWK' ('RSAGenParam' (4096 \`div` 8))
  let
    h = view 'thumbprint' jwk :: Digest SHA256
    kid = view (re ('Types.base64url' . 'digest') . utf8) h
  pure $ set 'jwkKid' (Just kid) jwk
@

-}
module Crypto.JOSE.JWK
  (
  -- * JWK generation
    genJWK
  , KeyMaterialGenParam(..)
  , Crv(..)
  , OKPCrv(..)
  , JWK
  , AsPublicKey(..)

  -- * Parts of a JWK
  , jwkMaterial
  , jwkUse
  , KeyUse(..)
  , jwkKeyOps
  , KeyOp(..)
  , jwkAlg
  , JWKAlg(..)
  , jwkKid
  , jwkX5u
  , jwkX5c
  , setJWKX5c
  , jwkX5t
  , jwkX5tS256

  -- * Converting from other key formats
  , fromKeyMaterial
  , fromRSA
  , fromRSAPublic
  , fromOctets
  , fromX509Certificate
  , fromX509PubKey
  , fromX509PrivKey

  -- * JWK Thumbprint
  , thumbprint
  , digest
  , Types.base64url
  , module Crypto.Hash

  -- * JWK Set
  , JWKSet(..)

  -- Miscellaneous
  , checkJWK
  , negotiateJWSAlg
  , bestJWSAlg

  , module Crypto.JOSE.JWA.JWK
  ) where

import Control.Applicative
import Control.Monad ((>=>))
import Data.Function (on)
import Data.List (find)
import Data.Maybe (catMaybes)
import Data.Word (Word8)

import Control.Lens hiding ((.=))
import Control.Lens.Cons.Extras (recons)
import Control.Monad.Except (MonadError, runExcept)
import Control.Monad.Error.Lens (throwing, throwing_)
import Crypto.Hash
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Curve448 as Curve448
import qualified Crypto.PubKey.RSA as RSA
import Data.Aeson
import Data.Aeson.Types (explicitParseFieldMaybe')
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Builder as Builder
import Data.List.NonEmpty
import qualified Data.Text as T
import qualified Data.X509 as X509

import Crypto.JOSE.Error
import qualified Crypto.JOSE.JWA.JWE.Alg as JWA.JWE
import Crypto.JOSE.JWA.JWK
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.TH
import qualified Crypto.JOSE.Types as Types
import Crypto.JOSE.Types.URI
import qualified Crypto.JOSE.Types.Internal as Types


-- | RFC 7517 §4.4.  "alg" (Algorithm) Parameter
--
-- See also RFC 7518 §6.4. which states that for "oct" keys, an
-- "alg" member SHOULD be present to identify the algorithm intended
-- to be used with the key, unless the application uses another
-- means or convention to determine the algorithm used.
--
data JWKAlg = JWSAlg JWA.JWS.Alg | JWEAlg JWA.JWE.Alg
  deriving (Eq, Show)

instance FromJSON JWKAlg where
  parseJSON v = (JWSAlg <$> parseJSON v) <|> (JWEAlg <$> parseJSON v)

instance ToJSON JWKAlg where
  toJSON (JWSAlg alg) = toJSON alg
  toJSON (JWEAlg alg) = toJSON alg


-- | RFC 7517 §4.3.  "key_ops" (Key Operations) Parameter
--
$(Crypto.JOSE.TH.deriveJOSEType "KeyOp"
  [ "sign", "verify", "encrypt", "decrypt"
  , "wrapKey", "unwrapKey", "deriveKey", "deriveBits"
  ])


-- | RFC 7517 §4.2.  "use" (Public Key Use) Parameter
--
$(Crypto.JOSE.TH.deriveJOSEType "KeyUse" ["sig", "enc"])


-- | RFC 7517 §4.  JSON Web Key (JWK) Format
--
data JWK = JWK
  {
    _jwkMaterial :: Crypto.JOSE.JWA.JWK.KeyMaterial
  , _jwkUse :: Maybe KeyUse
  , _jwkKeyOps :: Maybe [KeyOp]
  , _jwkAlg :: Maybe JWKAlg
  , _jwkKid :: Maybe T.Text
  , _jwkX5u :: Maybe Types.URI
  , _jwkX5cRaw :: Maybe (NonEmpty X509.SignedCertificate)
  , _jwkX5t :: Maybe Types.Base64SHA1
  , _jwkX5tS256 :: Maybe Types.Base64SHA256
  }
  deriving (Eq, Show)
makeLenses ''JWK

-- | Get the certificate chain.  Not a lens, because the key of the first
-- certificate in the chain must correspond be the public key of the JWK.
-- To set the certificate chain use 'setJWKX5c'.
--
jwkX5c :: Getter JWK (Maybe (NonEmpty X509.SignedCertificate))
jwkX5c = jwkX5cRaw

-- | Set the @"x5c"@ Certificate Chain parameter.  If setting the list,
-- checks that the key in the first certificate matches the JWK; returns
-- @Nothing@ if it does not.
--
setJWKX5c :: Maybe (NonEmpty X509.SignedCertificate) -> JWK -> Maybe JWK
setJWKX5c Nothing k = pure (set jwkX5cRaw Nothing k)
setJWKX5c certs@(Just (cert :| _)) key
  | certMatchesKey key cert = pure (set jwkX5cRaw certs key)
  | otherwise = Nothing

certMatchesKey :: JWK -> X509.SignedCertificate -> Bool
certMatchesKey key cert =
  maybe False (((==) `on` preview (jwkMaterial . asPublicKey)) key)
    (fromX509CertificateMaybe cert)


instance FromJSON JWK where
  parseJSON = withObject "JWK" (\o -> JWK
    <$> parseJSON (Object o)
    <*> o .:? "use"
    <*> o .:? "key_ops"
    <*> o .:? "alg"
    <*> o .:? "kid"
    <*> explicitParseFieldMaybe' uriFromJSON o "x5u"
    <*> ((fmap . fmap) (\(Types.Base64X509 cert) -> cert) <$> o .:? "x5c")
    <*> o .:? "x5t"
    <*> o .:? "x5t#S256"
    ) >=> checkKey
    where
    checkKey k
      | maybe False (not . certMatchesKey k . Data.List.NonEmpty.head) (view jwkX5c k)
        = fail "X.509 cert in \"x5c\" param does not match key"
      | otherwise = pure k

instance ToJSON JWK where
  toJSON JWK{..} = Types.insertManyToObject kvs (toJSON _jwkMaterial)
    where
      kvs = catMaybes
        [ fmap ("alg" .=) _jwkAlg
        , fmap ("use" .=) _jwkUse
        , fmap ("key_ops" .=) _jwkKeyOps
        , fmap ("kid" .=) _jwkKid
        , fmap ("x5u" .=) (uriToJSON <$> _jwkX5u)
        , fmap (("x5c" .=) . fmap Types.Base64X509) _jwkX5cRaw
        , fmap ("x5t" .=) _jwkX5t
        , fmap ("x5t#S256" .=) _jwkX5tS256
        ]

-- | Generate a JWK.  Apart from key parameters, no other parameters are set.
--
genJWK :: MonadRandom m => KeyMaterialGenParam -> m JWK
genJWK p = fromKeyMaterial <$> genKeyMaterial p

fromKeyMaterial :: KeyMaterial -> JWK
fromKeyMaterial k = JWK k z z z z z z z z where z = Nothing


-- | Convert RSA private key into a JWK
--
fromRSA :: RSA.PrivateKey -> JWK
fromRSA = fromKeyMaterial . RSAKeyMaterial . toRSAKeyParameters

-- | Convert an RSA public key into a JWK
--
fromRSAPublic :: RSA.PublicKey -> JWK
fromRSAPublic = fromKeyMaterial . RSAKeyMaterial . toRSAPublicKeyParameters


-- | Convert octet string into a JWK
--
fromOctets :: Cons s s Word8 Word8 => s -> JWK
fromOctets =
  fromKeyMaterial . OctKeyMaterial . OctKeyParameters . Types.Base64Octets
  . view recons
{-# INLINE fromOctets #-}


-- | Convert from a 'X509.PubKey' (such as can be read via the
-- /crypton-x509-store/ package).  Supports RSA, ECDSA, Ed25519,
-- Ed448, X25519 and X448 keys.
--
fromX509PubKey :: (AsError e, MonadError e m) => X509.PubKey -> m JWK
fromX509PubKey = \case
  X509.PubKeyRSA k      -> pure (fromRSAPublic k)
  X509.PubKeyEC k       -> fromECPublic k
  X509.PubKeyX25519 k   -> fromOKP $ X25519Key k Nothing
  X509.PubKeyX448 k     -> fromOKP $ X448Key k Nothing
  X509.PubKeyEd25519 k  -> fromOKP $ Ed25519Key k Nothing
  X509.PubKeyEd448 k    -> fromOKP $ Ed448Key k Nothing
  _ -> throwing _KeyMismatch "X.509 key type not supported"
  where
    fromECPublic = fmap (fromKeyMaterial . ECKeyMaterial) . ecParametersFromX509
    fromOKP = pure . fromKeyMaterial . OKPKeyMaterial

-- | Convert from a 'X509.PrivKey' (such as can be read via the
-- /crypton-x509-store/ package).  Supports RSA, ECDSA, Ed25519,
-- Ed448, X25519 and X448 keys.
--
fromX509PrivKey :: (AsError e, MonadError e m) => X509.PrivKey -> m JWK
fromX509PrivKey = \case
  X509.PrivKeyRSA k      -> pure (fromRSA k)
  X509.PrivKeyEC k       -> fromEC k
  X509.PrivKeyX25519 k   -> fromOKP $ X25519Key (Curve25519.toPublic k) (Just k)
  X509.PrivKeyX448 k     -> fromOKP $ X448Key (Curve448.toPublic k) (Just k)
  X509.PrivKeyEd25519 k  -> fromOKP $ Ed25519Key (Ed25519.toPublic k) (Just k)
  X509.PrivKeyEd448 k    -> fromOKP $ Ed448Key (Ed448.toPublic k) (Just k)
  _ -> throwing _KeyMismatch "X.509 key type not supported"
  where
    fromEC = fmap (fromKeyMaterial . ECKeyMaterial) . ecParametersFromX509Priv
    fromOKP = pure . fromKeyMaterial . OKPKeyMaterial


-- | Convert an X.509 certificate into a JWK.
--
-- Supports RSA, ECDSA (curves defined for use in JOSE), and Edwards
-- curves (Ed25519, Ed448, X25519, X448).
--
-- The @"x5c"@ field of the resulting JWK contains the certificate.
--
fromX509Certificate
  :: (AsError e, MonadError e m)
  => X509.SignedCertificate -> m JWK
fromX509Certificate cert = do
  k <- fromX509PubKey . X509.certPubKey . X509.signedObject $ X509.getSigned cert
  pure $ k & set jwkX5cRaw (Just (pure cert))

fromX509CertificateMaybe :: X509.SignedCertificate -> Maybe JWK
fromX509CertificateMaybe = f . runExcept . fromX509Certificate
  where
    f :: Either Error JWK -> Maybe JWK
    f (Left _) = Nothing
    f (Right jwk) = Just jwk


instance AsPublicKey JWK where
  asPublicKey = to (jwkMaterial (view asPublicKey))


-- | RFC 7517 §5.  JWK Set Format
--
newtype JWKSet = JWKSet [JWK] deriving (Eq, Show, Semigroup, Monoid)

instance FromJSON JWKSet where
  parseJSON = withObject "JWKSet" (\o -> JWKSet <$> o .: "keys")

instance ToJSON JWKSet where
  toJSON (JWKSet ks) = object ["keys" .= toJSON ks]


-- | Sanity-check a JWK.
--
-- Return an appropriate error if the key is size is too small to be
-- used with any JOSE algorithm, or for other problems that mean the
-- key cannot be used.
--
checkJWK :: (MonadError e m, AsError e) => JWK -> m ()
checkJWK jwk = case view jwkMaterial jwk of
  RSAKeyMaterial (view rsaN -> Types.Base64Integer n)
    | n >= 2 ^ (2040 :: Integer) -> pure ()
    | otherwise -> throwing _KeySizeTooSmall ()
  OctKeyMaterial (view octK -> Types.Base64Octets k)
    | B.length k >= 256 `div` 8 -> pure ()
    | otherwise -> throwing _KeySizeTooSmall ()
  _ -> pure ()


-- | Choose the cryptographically strongest JWS algorithm for a
-- given key.  The JWK "alg" algorithm parameter is ignored.
--
-- See also 'negotiateJWSAlg'.
--
-- @
-- bestJWSAlg k = negotiateJWSAlg k Nothing
-- @
--
bestJWSAlg
  :: (MonadError e m, AsError e)
  => JWK
  -> m JWA.JWS.Alg
bestJWSAlg jwk = chooseJWSAlg jwk Nothing

-- | Choose the cryptographically strongest JWS algorithm for a
-- given key, restricted to a given set of algorithms.  This
-- function supports negotiation use cases where verifier's
-- supported algorithms are advertised or known.
--
-- Throws an error if the key is too small or cannot be used for
-- signing, or if there is no overlap between the allowed algorithms
-- and the algorithms supported by the key type.
--
-- RSASSA-PSS algorithms are preferred over RSASSA-PKCS1-v1_5.
--
-- The JWK "alg" parameter is ignored.
--
negotiateJWSAlg
  :: (MonadError e m, AsError e)
  => JWK
  -> NonEmpty JWA.JWS.Alg
  -> m JWA.JWS.Alg
negotiateJWSAlg jwk = chooseJWSAlg jwk . Just

-- | General implementation used by 'bestJWSAlg' and 'negotiateJWSAlg'.
--
chooseJWSAlg
  :: (MonadError e m, AsError e)
  => JWK
  -> Maybe (NonEmpty JWA.JWS.Alg)
  -> m JWA.JWS.Alg
chooseJWSAlg jwk allowed = case view jwkMaterial jwk of
  ECKeyMaterial k -> case view ecCrv k of
    P_256     | ok JWA.JWS.ES256  -> pure JWA.JWS.ES256
    P_384     | ok JWA.JWS.ES384  -> pure JWA.JWS.ES384
    P_521     | ok JWA.JWS.ES512  -> pure JWA.JWS.ES512
    Secp256k1 | ok JWA.JWS.ES256K -> pure JWA.JWS.ES256K
    _                             -> negoFail
  RSAKeyMaterial k
    | n < 2 ^ (2040 :: Integer) -> throwing_ _KeySizeTooSmall
    | otherwise                 -> maybe negoFail pure (find ok rsaAlgs)
    where
      Types.Base64Integer n = view rsaN k
      rsaAlgs =
        [ JWA.JWS.PS512 , JWA.JWS.PS384 , JWA.JWS.PS256
        , JWA.JWS.RS512 , JWA.JWS.RS384 , JWA.JWS.RS256 ]
  OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))
    | B.length k >= 512 `div` 8, ok JWA.JWS.HS512 -> pure JWA.JWS.HS512
    | B.length k >= 384 `div` 8, ok JWA.JWS.HS384 -> pure JWA.JWS.HS384
    | B.length k >= 256 `div` 8, ok JWA.JWS.HS256 -> pure JWA.JWS.HS256
    | B.length k >= 256 `div` 8                   -> negoFail
    | otherwise                                   -> throwing_ _KeySizeTooSmall
  OKPKeyMaterial k -> case k of
    (X25519Key _ _)                     -> throwing _KeyMismatch "Cannot sign with X25519 key"
    (X448Key _ _)                       -> throwing _KeyMismatch "Cannot sign with X448 key"
    (Ed25519Key _ _) | ok JWA.JWS.EdDSA -> pure JWA.JWS.EdDSA
    (Ed448Key _ _)   | ok JWA.JWS.EdDSA -> pure JWA.JWS.EdDSA
    _                                   -> negoFail
  where
    ok alg = maybe True (alg `elem`) allowed
    negoFail = throwing _AlgorithmMismatch "Algorithm negotation failed"


-- | Compute the JWK Thumbprint of a JWK
--
thumbprint :: HashAlgorithm a => Getter JWK (Digest a)
thumbprint = to (hash . L.toStrict . thumbprintRepr)

-- | Prism from ByteString to @HashAlgorithm a => Digest a@.
--
-- Use @'re' digest@ to view the bytes of a digest
--
digest :: HashAlgorithm a => Prism' B.ByteString (Digest a)
digest = prism' BA.convert digestFromByteString

-- | JWK canonicalised for thumbprint computation
--
thumbprintRepr :: JWK -> L.ByteString
thumbprintRepr k = Builder.toLazyByteString . fromEncoding . pairs $
  case view jwkMaterial k of
    ECKeyMaterial k' -> "crv" .=
      view ecCrv k'
      <> "kty" .= ("EC" :: T.Text)
      <> "x" .= view ecX k'
      <> "y" .= view ecY k'
    RSAKeyMaterial k' ->
      "e" .= view rsaE k' <> "kty" .= ("RSA" :: T.Text) <> "n" .= view rsaN k'
    OctKeyMaterial (OctKeyParameters k') ->
      "k" .= k' <> "kty" .= ("oct" :: T.Text)
    OKPKeyMaterial (Ed25519Key pk _) -> okpSeries "Ed25519" pk
    OKPKeyMaterial (Ed448Key pk _) -> okpSeries "Ed448" pk
    OKPKeyMaterial (X25519Key pk _) -> okpSeries "X25519" pk
    OKPKeyMaterial (X448Key pk _) -> okpSeries "X448" pk
  where
    b64 = Types.Base64Octets . BA.convert
    okpSeries crv pk =
      "crv" .= (crv :: T.Text) <> "kty" .= ("OKP" :: T.Text) <> "x" .= b64 pk
