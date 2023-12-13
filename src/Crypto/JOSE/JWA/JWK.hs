-- Copyright (C) 2013-2018  Fraser Tweedale
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

{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

{-|

Cryptographic Algorithms for Keys.

-}
module Crypto.JOSE.JWA.JWK (
  -- * Type classes
    AsPublicKey(..)

  -- * Parameters for Elliptic Curve Keys
  , Crv(..)
  , ECKeyParameters(ECKeyParameters)
  , ecCrv, ecX, ecY, ecD
  , curve
  , point
  , ecPrivateKey
  , ecParametersFromX509
  , genEC

  -- * Parameters for RSA Keys
  , RSAPrivateKeyOthElem(..)
  , RSAPrivateKeyOptionalParameters(..)
  , RSAPrivateKeyParameters(..)
  , RSAKeyParameters(RSAKeyParameters)
  , toRSAKeyParameters
  , toRSAPublicKeyParameters
  , rsaE
  , rsaN
  , rsaPrivateKeyParameters
  , rsaPublicKey
  , genRSA

  -- * Parameters for Symmetric Keys
  , OctKeyParameters(..)
  , octK

  -- * Parameters for CFRG EC keys (RFC 8037)
  , OKPKeyParameters(..)
  , OKPCrv(..)
  , genOKP

  -- * Key generation
  , KeyMaterialGenParam(..)
  , KeyMaterial(..)
  , genKeyMaterial

  -- * Signing and verification
  , sign
  , verify

  , module Crypto.Random
  ) where

import Control.Monad (guard)
import Control.Monad.Except (MonadError)
import Data.Bifunctor
import Data.Foldable (toList)
import Data.Maybe (isJust)

import Control.Lens hiding ((.=), elements)
import Control.Monad.Error.Lens (throwing, throwing_)
import Crypto.Error (onCryptoFailure)
import Crypto.Hash
import Crypto.MAC.HMAC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Curve448 as Curve448
import Crypto.Random
import Data.Aeson
import qualified Data.Aeson.KeyMap as M
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.List.NonEmpty (NonEmpty)
import qualified Data.Text as T
import Data.X509 as X509
import Data.X509.EC as X509.EC

import Crypto.JOSE.Error
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.TH
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types


-- | \"crv\" (Curve) Parameter
--
$(Crypto.JOSE.TH.deriveJOSEType "Crv" ["P-256", "P-384", "P-521", "secp256k1"])


-- | \"oth\" (Other Primes Info) Parameter
--
data RSAPrivateKeyOthElem = RSAPrivateKeyOthElem {
  rOth :: Types.Base64Integer,
  dOth :: Types.Base64Integer,
  tOth :: Types.Base64Integer
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOthElem where
  parseJSON = withObject "oth" (\o -> RSAPrivateKeyOthElem <$>
    o .: "r" <*>
    o .: "d" <*>
    o .: "t")

instance ToJSON RSAPrivateKeyOthElem where
  toJSON (RSAPrivateKeyOthElem r d t) = object ["r" .= r, "d" .= d, "t" .= t]


-- | Optional parameters for RSA private keys
--
data RSAPrivateKeyOptionalParameters = RSAPrivateKeyOptionalParameters {
  rsaP :: Types.Base64Integer
  , rsaQ :: Types.Base64Integer
  , rsaDp :: Types.Base64Integer
  , rsaDq :: Types.Base64Integer
  , rsaQi :: Types.Base64Integer
  , rsaOth :: Maybe (NonEmpty RSAPrivateKeyOthElem)
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOptionalParameters where
  parseJSON = withObject "RSA" (\o -> RSAPrivateKeyOptionalParameters <$>
    o .: "p" <*>
    o .: "q" <*>
    o .: "dp" <*>
    o .: "dq" <*>
    o .: "qi" <*>
    o .:? "oth")

instance ToJSON RSAPrivateKeyOptionalParameters where
  toJSON RSAPrivateKeyOptionalParameters{..} = object $ [
    "p" .= rsaP
    , "q" .= rsaQ
    , "dp" .= rsaDp
    , "dq" .= rsaDq
    , "qi" .= rsaQi
    ] ++ maybe [] ((:[]) . ("oth" .=)) rsaOth


-- | RSA private key parameters
--
data RSAPrivateKeyParameters = RSAPrivateKeyParameters
  { rsaD :: Types.Base64Integer
  , rsaOptionalParameters :: Maybe RSAPrivateKeyOptionalParameters
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyParameters where
  parseJSON = withObject "RSA private key parameters" $ \o ->
    RSAPrivateKeyParameters
    <$> o .: "d"
    <*> (if any (`M.member` o) ["p", "q", "dp", "dq", "qi", "oth"]
      then Just <$> parseJSON (Object o)
      else pure Nothing)

instance ToJSON RSAPrivateKeyParameters where
  toJSON RSAPrivateKeyParameters {..} =
    Types.insertToObject "d" rsaD
      $ maybe (Object mempty) toJSON rsaOptionalParameters


-- | Parameters for Elliptic Curve Keys.
--
-- @
-- ECKeyParameters crv x y (Just d)
-- @
--
data ECKeyParameters = ECKeyParameters
  { _ecCrv :: Crv
  , _ecX :: Types.SizedBase64Integer
  , _ecY :: Types.SizedBase64Integer
  , _ecD :: Maybe Types.SizedBase64Integer
  }
  deriving (Eq, Show)

ecCrv :: Getter ECKeyParameters Crv
ecCrv = to (\(ECKeyParameters crv _ _ _) -> crv)

ecX, ecY :: Getter ECKeyParameters Types.SizedBase64Integer
ecX = to (\(ECKeyParameters _ x _ _) -> x)
ecY = to (\(ECKeyParameters _ _ y _) -> y)

ecD :: Getter ECKeyParameters (Maybe Types.SizedBase64Integer)
ecD = to (\(ECKeyParameters _ _ _ d) -> d)

instance FromJSON ECKeyParameters where
  parseJSON = withObject "EC" $ \o -> do
    o .: "kty" >>= guard . (== ("EC" :: T.Text))
    crv <- o .: "crv"
    let w = ecCoordBytes crv
    x <- o .: "x" >>= Types.checkSize w
    y <- o .: "y" >>= Types.checkSize w
    let int (Types.SizedBase64Integer _ n) = n
    if ECC.isPointValid (curve crv) (ECC.Point (int x) (int y))
      then ECKeyParameters crv x y
        <$> (o .:? "d" >>= traverse (Types.checkSize w))
      else fail "point is not on specified curve"

instance ToJSON ECKeyParameters where
  toJSON k = object $
    [ "kty" .= ("EC" :: T.Text)
    , "crv" .= view ecCrv k
    , "x" .= view ecX k
    , "y" .= view ecY k
    ] <> fmap ("d" .=) (toList (view ecD k))

genEC :: MonadRandom m => Crv -> m ECKeyParameters
genEC crv = do
  let i = Types.SizedBase64Integer (ecCoordBytes crv)
  (ECDSA.PublicKey _ p, ECDSA.PrivateKey _ d) <- ECC.generate (curve crv)
  case p of
    ECC.Point x y -> pure $ ECKeyParameters crv (i x) (i y) (Just (i d))
    ECC.PointO -> genEC crv  -- JWK cannot represent point at infinity; recurse

signEC
  :: (BA.ByteArrayAccess msg, HashAlgorithm h,
      MonadRandom m, MonadError e m, AsError e)
  => h
  -> ECKeyParameters
  -> msg
  -> m B.ByteString
signEC h k m = case view ecD k of
  Just ecD' -> sigToBS <$> sig where
    crv = view ecCrv k
    w = ecCoordBytes crv
    sig = ECDSA.sign privateKey h m
    sigToBS (ECDSA.Signature r s) =
      Types.sizedIntegerToBS w r <> Types.sizedIntegerToBS w s
    privateKey = ECDSA.PrivateKey (curve crv) (d ecD')
    d (Types.SizedBase64Integer _ n) = n
  Nothing -> throwing _KeyMismatch "not an EC private key"

verifyEC
  :: (BA.ByteArrayAccess msg, HashAlgorithm h)
  => h
  -> ECKeyParameters
  -> msg
  -> B.ByteString
  -> Bool
verifyEC h k m s = ECDSA.verify h pubkey sig m
  where
  pubkey = ECDSA.PublicKey (curve $ view ecCrv k) (point k)
  sig = uncurry ECDSA.Signature
    $ bimap Types.bsToInteger Types.bsToInteger
    $ B.splitAt (B.length s `div` 2) s

curve :: Crv -> ECC.Curve
curve = ECC.getCurveByName . review fromCurveName

-- | Conversion from known curves and back again.
fromCurveName :: Prism' ECC.CurveName Crv
fromCurveName = prism'
  (\case
    P_256 -> ECC.SEC_p256r1
    P_384 -> ECC.SEC_p384r1
    P_521 -> ECC.SEC_p521r1
    Secp256k1 -> ECC.SEC_p256k1)
  (\case
    ECC.SEC_p256r1 -> Just P_256
    ECC.SEC_p384r1 -> Just P_384
    ECC.SEC_p521r1 -> Just P_521
    ECC.SEC_p256k1 -> Just Secp256k1
    _              -> Nothing)

point :: ECKeyParameters -> ECC.Point
point k = ECC.Point (f ecX) (f ecY) where
  f l = case view l k of
    Types.SizedBase64Integer _ n -> n

ecCoordBytes :: Integral a => Crv -> a
ecCoordBytes P_256 = 32
ecCoordBytes P_384 = 48
ecCoordBytes P_521 = 66
ecCoordBytes Secp256k1 = 32

ecPrivateKey :: (MonadError e m, AsError e) => ECKeyParameters -> m Integer
ecPrivateKey (ECKeyParameters _ _ _ (Just (Types.SizedBase64Integer _ d))) = pure d
ecPrivateKey _ = throwing _KeyMismatch "Not an EC private key"

ecParametersFromX509 :: (MonadError e m, AsError e) => X509.PubKeyEC -> m ECKeyParameters
ecParametersFromX509 pubKeyEC = do
  ecCurve <- maybe (throwing _KeyMismatch "Invalid EC point") pure $ X509.EC.ecPubKeyCurve pubKeyEC
  curveName <- maybe (throwing _KeyMismatch "Unknown curve") pure $ X509.EC.ecPubKeyCurveName pubKeyEC
  crv <- maybe (throwing _KeyMismatch "Unsupported curve TODO ") pure $ preview fromCurveName curveName
  pt <- maybe (throwing _KeyMismatch "Invalid EC point") pure $ X509.EC.unserializePoint ecCurve (X509.pubkeyEC_pub pubKeyEC)
  (x, y) <- case pt of
    ECC.PointO    -> throwing _KeyMismatch "Cannot use point at infinity"
    ECC.Point x y ->
      pure (Types.makeSizedBase64Integer x, Types.makeSizedBase64Integer y)
  pure $ ECKeyParameters crv x y Nothing

-- | Parameters for RSA Keys.
--
-- @
-- RSAKeyParameters modulus exponent (Just privateParams)
-- @
--
data RSAKeyParameters = RSAKeyParameters
  { _rsaN :: Types.Base64Integer
  , _rsaE :: Types.Base64Integer
  , _rsaPrivateKeyParameters :: Maybe RSAPrivateKeyParameters
  }
  deriving (Eq, Show)
makeLenses ''RSAKeyParameters

instance FromJSON RSAKeyParameters where
  parseJSON = withObject "RSA" $ \o -> do
    o .: "kty" >>= guard . (== ("RSA" :: T.Text))
    RSAKeyParameters
      <$> o .: "n"
      <*> o .: "e"
      <*> if M.member "d" o
        then Just <$> parseJSON (Object o)
        else pure Nothing

instance ToJSON RSAKeyParameters where
  toJSON RSAKeyParameters {..} =
    Types.insertManyToObject
      [ "kty" .= ("RSA" :: T.Text)
      , "n" .= _rsaN
      , "e" .= _rsaE
      ]
      $ maybe (Object mempty) toJSON _rsaPrivateKeyParameters

genRSA :: MonadRandom m => Int -> m RSAKeyParameters
genRSA size = toRSAKeyParameters . snd <$> RSA.generate size 65537

toRSAKeyParameters :: RSA.PrivateKey -> RSAKeyParameters
toRSAKeyParameters priv@(RSA.PrivateKey pub _ _ _ _ _ _) =
  toRSAPublicKeyParameters pub
  & set rsaPrivateKeyParameters (pure $ toRSAPrivateKeyParameters priv)

toRSAPublicKeyParameters :: RSA.PublicKey -> RSAKeyParameters
toRSAPublicKeyParameters (RSA.PublicKey _ n e) =
  RSAKeyParameters (Types.Base64Integer n) (Types.Base64Integer e) Nothing

toRSAPrivateKeyParameters :: RSA.PrivateKey -> RSAPrivateKeyParameters
toRSAPrivateKeyParameters (RSA.PrivateKey _ d p q dp dq qi) =
  let i = Types.Base64Integer
  in RSAPrivateKeyParameters (i d)
      (Just (RSAPrivateKeyOptionalParameters (i p) (i q) (i dp) (i dq) (i qi) Nothing))

signPKCS15
  :: (PKCS15.HashAlgorithmASN1 h, MonadRandom m, MonadError e m, AsError e)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> m B.ByteString
signPKCS15 h k m = do
  k' <- rsaPrivateKey k
  PKCS15.signSafer (Just h) k' m
    >>= either (throwing _RSAError) pure

verifyPKCS15
  :: PKCS15.HashAlgorithmASN1 h
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Bool
verifyPKCS15 h k = PKCS15.verify (Just h) (rsaPublicKey k)

signPSS
  :: (HashAlgorithm h, MonadRandom m, MonadError e m, AsError e)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> m B.ByteString
signPSS h k m = do
  k' <- rsaPrivateKey k
  PSS.signSafer (PSS.defaultPSSParams h) k' m
    >>= either (throwing _RSAError) pure

verifyPSS
  :: (HashAlgorithm h)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Bool
verifyPSS h k = PSS.verify (PSS.defaultPSSParams h) (rsaPublicKey k)

rsaPrivateKey
  :: (MonadError e m, AsError e)
  => RSAKeyParameters -> m RSA.PrivateKey
rsaPrivateKey (RSAKeyParameters
  (Types.Base64Integer n)
  (Types.Base64Integer e)
  (Just (RSAPrivateKeyParameters (Types.Base64Integer d) opt)))
  | isJust (opt >>= rsaOth) = throwing_ _OtherPrimesNotSupported
  | n < 2 ^ (2040 :: Integer) = throwing_ _KeySizeTooSmall
  | otherwise = pure $
    RSA.PrivateKey (RSA.PublicKey (Types.intBytes n) n e) d
      (opt' rsaP) (opt' rsaQ) (opt' rsaDp) (opt' rsaDq) (opt' rsaQi)
    where
      opt' f = maybe 0 (unB64I . f) opt
      unB64I (Types.Base64Integer x) = x
rsaPrivateKey _ = throwing _KeyMismatch "not an RSA private key"

rsaPublicKey :: RSAKeyParameters -> RSA.PublicKey
rsaPublicKey (RSAKeyParameters (Types.Base64Integer n) (Types.Base64Integer e) _)
  = RSA.PublicKey (Types.intBytes n) n e


-- | Symmetric key parameters data.
--
newtype OctKeyParameters = OctKeyParameters Types.Base64Octets
  deriving (Eq, Show)

octK :: Iso' OctKeyParameters Types.Base64Octets
octK = iso (\(OctKeyParameters k) -> k) OctKeyParameters

instance FromJSON OctKeyParameters where
  parseJSON = withObject "symmetric key" $ \o -> do
    o .: "kty" >>= guard . (== ("oct" :: T.Text))
    OctKeyParameters <$> o .: "k"

instance ToJSON OctKeyParameters where
  toJSON k = object
    [ "kty" .= ("oct" :: T.Text)
    , "k" .= (view octK k :: Types.Base64Octets)
    ]

signOct
  :: forall h e m. (HashAlgorithm h, MonadError e m, AsError e)
  => h
  -> OctKeyParameters
  -> B.ByteString
  -> m B.ByteString
signOct h (OctKeyParameters (Types.Base64Octets k)) m =
  if B.length k < hashDigestSize h
  then throwing_ _KeySizeTooSmall
  else pure $ B.pack $ BA.unpack (hmac k m :: HMAC h)


-- "OKP" (CFRG Octet Key Pair) keys (RFC 8037)
--
data OKPKeyParameters
  = Ed25519Key Ed25519.PublicKey (Maybe Ed25519.SecretKey)
  | Ed448Key Ed448.PublicKey (Maybe Ed448.SecretKey)
  | X25519Key Curve25519.PublicKey (Maybe Curve25519.SecretKey)
  | X448Key Curve448.PublicKey (Maybe Curve448.SecretKey)
  deriving (Eq)

instance Show OKPKeyParameters where
  show = \case
      Ed25519Key pk sk  -> "Ed25519 " <> showKeys pk sk
      Ed448Key pk sk  -> "Ed448 " <> showKeys pk sk
      X25519Key pk sk   -> "X25519 " <> showKeys pk sk
      X448Key pk sk   -> "X448 " <> showKeys pk sk
    where
      showKeys pk sk = show pk <> " " <> show (("SECRET" :: String) <$ sk)

instance FromJSON OKPKeyParameters where
  parseJSON = withObject "OKP" $ \o -> do
    o .: "kty" >>= guard . (== ("OKP" :: T.Text))
    crv <- o .: "crv"
    case (crv :: T.Text) of
      "Ed25519" -> parseOKPKey Ed25519Key Ed25519.publicKey Ed25519.secretKey o
      "X25519"  -> parseOKPKey X25519Key Curve25519.publicKey Curve25519.secretKey o
      "Ed448"   -> parseOKPKey Ed448Key Ed448.publicKey Ed448.secretKey o
      "X448"    -> parseOKPKey X448Key Curve448.publicKey Curve448.secretKey o
      _         -> fail "unrecognised OKP key subtype"
    where
      bs (Types.Base64Octets k) = k
      handleError = onCryptoFailure (fail . show) pure
      parseOKPKey con mkPub mkSec o = con
        <$> (o .: "x" >>= handleError . mkPub . bs)
        <*> (o .:? "d" >>= traverse (handleError . mkSec . bs))

instance ToJSON OKPKeyParameters where
  toJSON x = object $
    "kty" .= ("OKP" :: T.Text) : case x of
      Ed25519Key pk sk -> "crv" .= ("Ed25519" :: T.Text) : params pk sk
      Ed448Key pk sk -> "crv" .= ("Ed448" :: T.Text) : params pk sk
      X25519Key pk sk  -> "crv" .= ("X25519" :: T.Text) : params pk sk
      X448Key pk sk  -> "crv" .= ("X448" :: T.Text) : params pk sk
    where
      b64 = Types.Base64Octets . BA.convert
      params pk sk = "x" .= b64 pk : (("d" .=) . b64 <$> toList sk)

data OKPCrv = Ed25519 | Ed448 | X25519 | X448
  deriving (Eq, Show)

genOKP :: MonadRandom m => OKPCrv -> m OKPKeyParameters
genOKP = \case
  Ed25519 -> Ed25519.generateSecretKey >>= \k -> pure (Ed25519Key (Ed25519.toPublic k) (Just k))
  Ed448 -> Ed448.generateSecretKey >>= \k -> pure (Ed448Key (Ed448.toPublic k) (Just k))
  X25519 -> Curve25519.generateSecretKey >>= \k -> pure (X25519Key (Curve25519.toPublic k) (Just k))
  X448 -> Curve448.generateSecretKey >>= \k -> pure (X448Key (Curve448.toPublic k) (Just k))

signEdDSA
  :: (MonadError e m, AsError e)
  => OKPKeyParameters
  -> B.ByteString
  -> m B.ByteString
signEdDSA (Ed25519Key pk (Just sk)) m = pure . BA.convert $ Ed25519.sign sk pk m
signEdDSA (Ed25519Key _   Nothing)  _ = throwing _KeyMismatch "not a private key"
signEdDSA (Ed448Key pk (Just sk))   m = pure . BA.convert $ Ed448.sign sk pk m
signEdDSA (Ed448Key _   Nothing)    _ = throwing _KeyMismatch "not a private key"
signEdDSA (X25519Key _ _) _ = throwing _KeyMismatch "not an EdDSA key"
signEdDSA (X448Key _ _)   _ = throwing _KeyMismatch "not an EdDSA key"

verifyEdDSA
  :: (BA.ByteArrayAccess msg, BA.ByteArrayAccess sig, MonadError e m, AsError e)
  => OKPKeyParameters -> msg -> sig -> m Bool
verifyEdDSA (Ed25519Key pk _) m s =
  onCryptoFailure
    (throwing _CryptoError)
    (pure . Ed25519.verify pk m)
    (Ed25519.signature s)
verifyEdDSA (Ed448Key pk _) m s =
  onCryptoFailure
    (throwing _CryptoError)
    (pure . Ed448.verify pk m)
    (Ed448.signature s)
verifyEdDSA (X25519Key _ _) _ _ = throwing _AlgorithmMismatch "not an EdDSA key"
verifyEdDSA (X448Key _ _)   _ _ = throwing _AlgorithmMismatch "not an EdDSA key"


-- | Key material sum type.
--
data KeyMaterial
  = ECKeyMaterial ECKeyParameters
  | RSAKeyMaterial RSAKeyParameters
  | OctKeyMaterial OctKeyParameters
  | OKPKeyMaterial OKPKeyParameters
  deriving (Eq, Show)

showKeyType :: KeyMaterial -> String
showKeyType (ECKeyMaterial ECKeyParameters{ _ecCrv = crv }) = "ECDSA (" ++ show crv ++ ")"
showKeyType (RSAKeyMaterial _) = "RSA"
showKeyType (OctKeyMaterial _) = "symmetric"
showKeyType (OKPKeyMaterial _) = "OKP"

instance FromJSON KeyMaterial where
  parseJSON = withObject "KeyMaterial" $ \o ->
    case M.lookup "kty" o of
      Nothing     -> fail "missing \"kty\" parameter"
      Just "EC"   -> ECKeyMaterial  <$> parseJSON (Object o)
      Just "RSA"  -> RSAKeyMaterial <$> parseJSON (Object o)
      Just "oct"  -> OctKeyMaterial <$> parseJSON (Object o)
      Just "OKP"  -> OKPKeyMaterial <$> parseJSON (Object o)
      Just s      -> fail $ "unsupported \"kty\": " <> show s

instance ToJSON KeyMaterial where
  toJSON (ECKeyMaterial p)  = toJSON p
  toJSON (RSAKeyMaterial p) = toJSON p
  toJSON (OctKeyMaterial p) = toJSON p
  toJSON (OKPKeyMaterial p) = toJSON p

-- | Keygen parameters.
--
data KeyMaterialGenParam
  = ECGenParam Crv
  -- ^ Generate an EC key with specified curve.
  | RSAGenParam Int
  -- ^ Generate an RSA key with specified size in /bytes/.
  | OctGenParam Int
  -- ^ Generate a symmetric key with specified size in /bytes/.
  | OKPGenParam OKPCrv
  -- ^ Generate an EdDSA or Edwards ECDH key with specified curve.
  deriving (Eq, Show)

genKeyMaterial :: MonadRandom m => KeyMaterialGenParam -> m KeyMaterial
genKeyMaterial (ECGenParam crv) = ECKeyMaterial <$> genEC crv
genKeyMaterial (RSAGenParam size) = RSAKeyMaterial <$> genRSA size
genKeyMaterial (OctGenParam n) =
  OctKeyMaterial . OctKeyParameters . Types.Base64Octets <$> getRandomBytes n
genKeyMaterial (OKPGenParam crv) = OKPKeyMaterial <$> genOKP crv

sign
  :: (MonadRandom m, MonadError e m, AsError e)
  => JWA.JWS.Alg
  -> KeyMaterial
  -> B.ByteString
  -> m B.ByteString
sign JWA.JWS.None _ = \_ -> return ""
sign JWA.JWS.ES256 (ECKeyMaterial k@ECKeyParameters{ _ecCrv = P_256 }) = signEC SHA256 k
sign JWA.JWS.ES384 (ECKeyMaterial k@ECKeyParameters{ _ecCrv = P_384 }) = signEC SHA384 k
sign JWA.JWS.ES512 (ECKeyMaterial k@ECKeyParameters{ _ecCrv = P_521 }) = signEC SHA512 k
sign JWA.JWS.ES256K (ECKeyMaterial k@ECKeyParameters{ _ecCrv = Secp256k1 }) = signEC SHA256 k
sign JWA.JWS.RS256 (RSAKeyMaterial k) = signPKCS15 SHA256 k
sign JWA.JWS.RS384 (RSAKeyMaterial k) = signPKCS15 SHA384 k
sign JWA.JWS.RS512 (RSAKeyMaterial k) = signPKCS15 SHA512 k
sign JWA.JWS.PS256 (RSAKeyMaterial k) = signPSS SHA256 k
sign JWA.JWS.PS384 (RSAKeyMaterial k) = signPSS SHA384 k
sign JWA.JWS.PS512 (RSAKeyMaterial k) = signPSS SHA512 k
sign JWA.JWS.HS256 (OctKeyMaterial k) = signOct SHA256 k
sign JWA.JWS.HS384 (OctKeyMaterial k) = signOct SHA384 k
sign JWA.JWS.HS512 (OctKeyMaterial k) = signOct SHA512 k
sign JWA.JWS.EdDSA (OKPKeyMaterial k) = signEdDSA k
sign h k = \_ -> throwing _AlgorithmMismatch
  (show h <> " cannot be used with " <> showKeyType k <> " key")

verify
  :: (MonadError e m, AsError e)
  => JWA.JWS.Alg
  -> KeyMaterial
  -> B.ByteString
  -> B.ByteString
  -> m Bool
verify JWA.JWS.None _ = \_ s -> pure $ s == ""
verify JWA.JWS.ES256 (ECKeyMaterial k@ECKeyParameters{ _ecCrv = P_256 }) = fmap pure . verifyEC SHA256 k
verify JWA.JWS.ES384 (ECKeyMaterial k@ECKeyParameters{ _ecCrv = P_384 }) = fmap pure . verifyEC SHA384 k
verify JWA.JWS.ES512 (ECKeyMaterial k@ECKeyParameters{ _ecCrv = P_521 }) = fmap pure . verifyEC SHA512 k
verify JWA.JWS.ES256K (ECKeyMaterial k@ECKeyParameters{ _ecCrv = Secp256k1 }) = fmap pure . verifyEC SHA256 k
verify JWA.JWS.RS256 (RSAKeyMaterial k) = fmap pure . verifyPKCS15 SHA256 k
verify JWA.JWS.RS384 (RSAKeyMaterial k) = fmap pure . verifyPKCS15 SHA384 k
verify JWA.JWS.RS512 (RSAKeyMaterial k) = fmap pure . verifyPKCS15 SHA512 k
verify JWA.JWS.PS256 (RSAKeyMaterial k) = fmap pure . verifyPSS SHA256 k
verify JWA.JWS.PS384 (RSAKeyMaterial k) = fmap pure . verifyPSS SHA384 k
verify JWA.JWS.PS512 (RSAKeyMaterial k) = fmap pure . verifyPSS SHA512 k
verify JWA.JWS.HS256 (OctKeyMaterial k) = \m s -> BA.constEq s <$> signOct SHA256 k m
verify JWA.JWS.HS384 (OctKeyMaterial k) = \m s -> BA.constEq s <$> signOct SHA384 k m
verify JWA.JWS.HS512 (OctKeyMaterial k) = \m s -> BA.constEq s <$> signOct SHA512 k m
verify JWA.JWS.EdDSA (OKPKeyMaterial k) = verifyEdDSA k
verify h k = \_ _ -> throwing _AlgorithmMismatch
  (show h <> " cannot be used with " <> showKeyType k <> " key")


-- | Keys that may have have public material
--
class AsPublicKey k where
  -- | Get the public key
  asPublicKey :: Getter k (Maybe k)


instance AsPublicKey RSAKeyParameters where
  asPublicKey = to (Just . set rsaPrivateKeyParameters Nothing)

instance AsPublicKey ECKeyParameters where
  asPublicKey = to (\k -> Just k { _ecD = Nothing })

instance AsPublicKey OKPKeyParameters where
  asPublicKey = to $ \case
    Ed25519Key  pk _  -> Just (Ed25519Key pk Nothing)
    Ed448Key    pk _  -> Just (Ed448Key pk Nothing)
    X25519Key   pk _  -> Just (X25519Key pk Nothing)
    X448Key     pk _  -> Just (X448Key pk Nothing)

instance AsPublicKey KeyMaterial where
  asPublicKey = to $ \case
    OctKeyMaterial _  -> Nothing
    RSAKeyMaterial k  -> RSAKeyMaterial  <$> view asPublicKey k
    ECKeyMaterial k   -> ECKeyMaterial   <$> view asPublicKey k
    OKPKeyMaterial k  -> OKPKeyMaterial  <$> view asPublicKey k
