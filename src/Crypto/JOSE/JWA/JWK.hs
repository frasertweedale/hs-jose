-- Copyright (C) 2013, 2014, 2015  Fraser Tweedale
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
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeFamilies #-}

{-|

Cryptographic Algorithms for Keys.

-}
module Crypto.JOSE.JWA.JWK (
  -- * \"kty\" (Key Type) Parameter Values
    EC(..)
  , RSA(..)
  , Oct(..)

  -- * Parameters for Elliptic Curve Keys
  , Crv(..)
  , ECKeyParameters(..)

  -- * Parameters for RSA Keys
  , RSAPrivateKeyOthElem(..)
  , RSAPrivateKeyOptionalParameters(..)
  , RSAPrivateKeyParameters(..)
  , RSAKeyParameters(RSAKeyParameters)
  , rsaE
  , rsaKty
  , rsaN
  , rsaPrivateKeyParameters

  -- * Parameters for Symmetric Keys
  , OctKeyParameters(..)

  , KeyMaterialGenParam(..)
  , KeyMaterial(..)

  , module Crypto.JOSE.Classes
  ) where

import Control.Applicative
import Data.Bifunctor
import Data.Maybe

import Control.Lens hiding ((.=))
import Crypto.Hash
import Crypto.MAC.HMAC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.PubKey.ECC.Types as ECC
import Crypto.Random
import Data.Aeson
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.HashMap.Strict as M
import Data.List.NonEmpty
import Test.QuickCheck

import Crypto.JOSE.Error
import Crypto.JOSE.Classes
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.TH
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types


-- | Elliptic Curve key type (Recommeded+)
$(Crypto.JOSE.TH.deriveJOSEType "EC" ["EC"])
-- | RSA key type (Required)
$(Crypto.JOSE.TH.deriveJOSEType "RSA" ["RSA"])
-- | Octet sequence (symmetric key) key type (Required)
$(Crypto.JOSE.TH.deriveJOSEType "Oct" ["oct"])


-- | \"crv\" (Curve) Parameter
--
$(Crypto.JOSE.TH.deriveJOSEType "Crv" ["P-256", "P-384", "P-521"])

instance Arbitrary Crv where
  arbitrary = oneof $ pure <$> [P_256, P_384, P_521]


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
  toJSON (RSAPrivateKeyOptionalParameters {..}) = object $ [
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
  toJSON RSAPrivateKeyParameters {..} = object $
    ("d" .= rsaD) : maybe [] (Types.objectPairs . toJSON) rsaOptionalParameters


-- | Parameters for Elliptic Curve Keys
--
data ECKeyParameters = ECKeyParameters
  {
    ecKty :: EC
  , ecCrv :: Crv
  , ecX :: Types.SizedBase64Integer
  , ecY :: Types.SizedBase64Integer
  , ecD :: Maybe Types.SizedBase64Integer
  }
  deriving (Eq, Show)

instance FromJSON ECKeyParameters where
  parseJSON = withObject "EC" $ \o -> do
    crv <- o .: "crv"
    ECKeyParameters
      <$> o .: "kty"
      <*> pure crv
      <*> (o .: "x" >>= Types.checkSize (ecCoordBytes crv))
      <*> (o .: "y" >>= Types.checkSize (ecCoordBytes crv))
      <*> (o .:? "d" >>= \case
        Nothing -> return Nothing
        Just v -> Just <$> Types.checkSize (ecDBytes crv) v)

instance ToJSON ECKeyParameters where
  toJSON (ECKeyParameters {..}) = object $
    [ "crv" .= ecCrv
    , "x" .= ecX
    , "y" .= ecY
    ] ++ fmap ("d" .=) (maybeToList ecD)

instance Key ECKeyParameters where
  type KeyGenParam ECKeyParameters = Crv
  type KeyContent ECKeyParameters = ECKeyParameters
  gen crv = do
    let
      xyValue = Types.SizedBase64Integer (ecCoordBytes crv)
      dValue = Types.SizedBase64Integer (ecDBytes crv)
    (ECDSA.PublicKey _ p, ECDSA.PrivateKey _ d) <- ECC.generate (curve crv)
    case p of
      ECC.Point x y -> return $
        ECKeyParameters EC crv (xyValue x) (xyValue y) (Just (dValue d))
      ECC.PointO -> gen crv  -- JWK cannot represent point at infinity; recurse
  fromKeyContent = id
  sign JWA.JWS.ES256 k@(ECKeyParameters { ecCrv = P_256 }) = signEC SHA256 k
  sign JWA.JWS.ES384 k@(ECKeyParameters { ecCrv = P_384 }) = signEC SHA384 k
  sign JWA.JWS.ES512 k@(ECKeyParameters { ecCrv = P_521 }) = signEC SHA512 k
  sign h _ = \_ ->
    return (Left $ AlgorithmMismatch  $ show h ++ "cannot be used with EC key")
  verify JWA.JWS.ES256 = verifyEC SHA256
  verify JWA.JWS.ES384 = verifyEC SHA384
  verify JWA.JWS.ES512 = verifyEC SHA512
  verify h = \_ _ _ ->
    Left $ AlgorithmMismatch  $ show h ++ "cannot be used with EC key"
  public k = Just k { ecD = Nothing }

instance Arbitrary ECKeyParameters where
  arbitrary = do
    crv <- arbitrary
    let w = ecCoordBytes crv
    ECKeyParameters EC crv
      <$> Types.genSizedBase64IntegerOf w
      <*> Types.genSizedBase64IntegerOf w
      <*> oneof
        [ pure Nothing
        , Just <$> Types.genSizedBase64IntegerOf (ecDBytes crv)
        ]

signEC
  :: (BA.ByteArrayAccess msg, HashAlgorithm h, MonadRandom m)
  => h
  -> ECKeyParameters
  -> msg
  -> m (Either Error B.ByteString)
signEC h (ECKeyParameters {..}) m = case ecD of
  Just ecD' -> Right . sigToBS <$> sig where
    w = ecCoordBytes ecCrv
    sig = ECDSA.sign privateKey h m
    sigToBS (ECDSA.Signature r s) =
      Types.sizedIntegerToBS w r `B.append` Types.sizedIntegerToBS w s
    privateKey = ECDSA.PrivateKey (curve ecCrv) (d ecD')
    d (Types.SizedBase64Integer _ n) = n
  Nothing -> return (Left $ KeyMismatch "not an EC private key")

verifyEC
  :: (BA.ByteArrayAccess msg, HashAlgorithm h)
  => h
  -> ECKeyParameters
  -> msg
  -> B.ByteString
  -> Either Error Bool
verifyEC h k m s = Right $ ECDSA.verify h pubkey sig m
  where
  pubkey = ECDSA.PublicKey (curve $ ecCrv k) (point k)
  sig = uncurry ECDSA.Signature
    $ bimap Types.bsToInteger Types.bsToInteger
    $ B.splitAt (B.length s `div` 2) s

curve :: Crv -> ECC.Curve
curve = ECC.getCurveByName . curveName where
  curveName P_256 = ECC.SEC_p256r1
  curveName P_384 = ECC.SEC_p384r1
  curveName P_521 = ECC.SEC_p521r1

point :: ECKeyParameters -> ECC.Point
point ECKeyParameters {..} = ECC.Point (integer ecX) (integer ecY) where
  integer (Types.SizedBase64Integer _ n) = n

ecCoordBytes :: Integral a => Crv -> a
ecCoordBytes P_256 = 32
ecCoordBytes P_384 = 48
ecCoordBytes P_521 = 66

ecDBytes :: Integral a => Crv -> a
ecDBytes crv = ceiling (logBase 2 (fromIntegral order) / 8 :: Double) where
  order = ECC.ecc_n $ ECC.common_curve $ curve crv


-- | Parameters for RSA Keys
--
data RSAKeyParameters = RSAKeyParameters
  { _rsaKty :: RSA
  , _rsaN :: Types.SizedBase64Integer
  , _rsaE :: Types.Base64Integer
  , _rsaPrivateKeyParameters :: Maybe RSAPrivateKeyParameters
  }
  deriving (Eq, Show)
makeLenses ''RSAKeyParameters

instance FromJSON RSAKeyParameters where
  parseJSON = withObject "RSA" $ \o ->
    RSAKeyParameters
      <$> o .: "kty"
      <*> o .: "n"
      <*> o .: "e"
      <*> if M.member "d" o
        then Just <$> parseJSON (Object o)
        else pure Nothing

instance ToJSON RSAKeyParameters where
  toJSON RSAKeyParameters {..} = object $
      ("kty" .= _rsaKty)
    : ("n" .= _rsaN)
    : ("e" .= _rsaE)
    : maybe [] (Types.objectPairs . toJSON) _rsaPrivateKeyParameters

instance Key RSAKeyParameters where
  type KeyGenParam RSAKeyParameters = Int   -- ^ Size of key in /bytes/
  type KeyContent RSAKeyParameters =
    ( Types.SizedBase64Integer
    , Types.Base64Integer
    , Maybe RSAPrivateKeyParameters
    )
  gen size = do
    (RSA.PublicKey s n e, RSA.PrivateKey _ d p q dp dq qi) <- RSA.generate size 65537
    let i = Types.Base64Integer
    return $ fromKeyContent
      ( Types.SizedBase64Integer s n
      , i e
      , Just (RSAPrivateKeyParameters (i d)
        (Just (RSAPrivateKeyOptionalParameters
          (i p) (i q) (i dp) (i dq) (i qi) Nothing))) )
  fromKeyContent (n, e, p) = RSAKeyParameters RSA n e p
  public = Just . set rsaPrivateKeyParameters Nothing
  sign JWA.JWS.RS256 = signPKCS15 SHA256
  sign JWA.JWS.RS384 = signPKCS15 SHA384
  sign JWA.JWS.RS512 = signPKCS15 SHA512
  sign JWA.JWS.PS256 = signPSS SHA256
  sign JWA.JWS.PS384 = signPSS SHA384
  sign JWA.JWS.PS512 = signPSS SHA512
  sign h = \_ _ ->
    return (Left $ AlgorithmMismatch  $ show h ++ " cannot be used with RSA key")
  verify JWA.JWS.RS256 = verifyPKCS15 SHA256
  verify JWA.JWS.RS384 = verifyPKCS15 SHA384
  verify JWA.JWS.RS512 = verifyPKCS15 SHA512
  verify JWA.JWS.PS256 = verifyPSS SHA256
  verify JWA.JWS.PS384 = verifyPSS SHA384
  verify JWA.JWS.PS512 = verifyPSS SHA512
  verify h = \_ _ _ ->
    Left $ AlgorithmMismatch  $ show h ++ "cannot be used with RSA key"

signPKCS15
  :: (PKCS15.HashAlgorithmASN1 h, MonadRandom m)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> m (Either Error B.ByteString)
signPKCS15 h k m = case rsaPrivateKey k of
  Left e -> return (Left e)
  Right k' -> first RSAError <$> PKCS15.signSafer (Just h) k' m

verifyPKCS15
  :: PKCS15.HashAlgorithmASN1 h
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Either Error Bool
verifyPKCS15 h k m = Right . PKCS15.verify (Just h) (rsaPublicKey k) m

signPSS
  :: (HashAlgorithm h, MonadRandom m)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> m (Either Error B.ByteString)
signPSS h k m = case rsaPrivateKey k of
  Left e -> return (Left e)
  Right k' -> first RSAError <$> PSS.signSafer (PSS.defaultPSSParams h) k' m

verifyPSS
  :: (HashAlgorithm h)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Either Error Bool
verifyPSS h k m = Right .
  PSS.verify (PSS.defaultPSSParams h) (rsaPublicKey k) m

rsaPrivateKey :: RSAKeyParameters -> Either Error RSA.PrivateKey
rsaPrivateKey (RSAKeyParameters _
  (Types.SizedBase64Integer size n)
  (Types.Base64Integer e)
  (Just (RSAPrivateKeyParameters (Types.Base64Integer d) opt)))
  | isJust (opt >>= rsaOth) = Left OtherPrimesNotSupported
  | size < 2048 `div` 8 = Left KeySizeTooSmall
  | otherwise = Right $
    RSA.PrivateKey (RSA.PublicKey size n e) d
      (opt' rsaP) (opt' rsaQ) (opt' rsaDp) (opt' rsaDq) (opt' rsaQi)
    where
      opt' f = fromMaybe 0 (unB64I . f <$> opt)
      unB64I (Types.Base64Integer x) = x

rsaPrivateKey _ = Left $ KeyMismatch "not an RSA private key"

rsaPublicKey :: RSAKeyParameters -> RSA.PublicKey
rsaPublicKey (RSAKeyParameters _
  (Types.SizedBase64Integer size n) (Types.Base64Integer e) _)
  = RSA.PublicKey size n e


-- | Symmetric key parameters data.
--
data OctKeyParameters = OctKeyParameters
  { octKty :: Oct
  , octK :: Types.Base64Octets
  }
  deriving (Eq, Show)

instance FromJSON OctKeyParameters where
  parseJSON = withObject "symmetric key" $ \o ->
    OctKeyParameters <$> o .: "kty" <*> o .: "k"

instance ToJSON OctKeyParameters where
  toJSON OctKeyParameters {..} = object ["kty" .= octKty, "k" .= octK]

instance Key OctKeyParameters where
  type KeyGenParam OctKeyParameters = Int   -- ^ Size of key in /bytes/
  type KeyContent OctKeyParameters = Types.Base64Octets
  gen n = fromKeyContent . Types.Base64Octets <$> getRandomBytes n
  fromKeyContent = OctKeyParameters Oct
  public = const Nothing
  sign JWA.JWS.HS256 k = return . Right . signOct SHA256 k
  sign JWA.JWS.HS384 k = return . Right . signOct SHA384 k
  sign JWA.JWS.HS512 k = return . Right . signOct SHA512 k
  sign h _ = const $ return $
    Left $ AlgorithmMismatch $ show h ++ "cannot be used with Oct key"
  verify JWA.JWS.HS256 k m s = Right $ signOct SHA256 k m `BA.constEq` s
  verify JWA.JWS.HS384 k m s = Right $ signOct SHA384 k m `BA.constEq` s
  verify JWA.JWS.HS512 k m s = Right $ signOct SHA512 k m `BA.constEq` s
  verify h _ _ _ =
    Left $ AlgorithmMismatch $ show h ++ "cannot be used with Oct key"

signOct
  :: forall h. HashAlgorithm h
  => h
  -> OctKeyParameters
  -> B.ByteString
  -> B.ByteString
signOct _ (OctKeyParameters _ (Types.Base64Octets k)) m
  = B.pack $ BA.unpack (hmac k m :: HMAC h)


-- | Key material sum type.
--
data KeyMaterial
  = ECKeyMaterial ECKeyParameters
  | RSAKeyMaterial RSAKeyParameters
  | OctKeyMaterial OctKeyParameters
  deriving (Eq, Show)

instance FromJSON KeyMaterial where
  parseJSON = withObject "KeyMaterial" $ \o ->
    ECKeyMaterial      <$> parseJSON (Object o)
    <|> RSAKeyMaterial <$> parseJSON (Object o)
    <|> OctKeyMaterial <$> parseJSON (Object o)

instance ToJSON KeyMaterial where
  toJSON (ECKeyMaterial p)  = object $ Types.objectPairs (toJSON p)
  toJSON (RSAKeyMaterial p) = object $ Types.objectPairs (toJSON p)
  toJSON (OctKeyMaterial p) = object $ Types.objectPairs (toJSON p)

-- | Keygen parameters.
--
data KeyMaterialGenParam
  = ECGenParam Crv
  | RSAGenParam Int
  | OctGenParam Int

instance Key KeyMaterial where
  type KeyGenParam KeyMaterial = KeyMaterialGenParam
  type KeyContent KeyMaterial = KeyMaterial
  gen (ECGenParam a) = ECKeyMaterial <$> gen a
  gen (RSAGenParam a) = RSAKeyMaterial <$> gen a
  gen (OctGenParam a) = OctKeyMaterial <$> gen a
  fromKeyContent = id
  public (ECKeyMaterial k) = ECKeyMaterial <$> public k
  public (RSAKeyMaterial k) = RSAKeyMaterial <$> public k
  public (OctKeyMaterial k) = OctKeyMaterial <$> public k
  sign JWA.JWS.None _ = \_ -> return $ Right ""
  sign h (ECKeyMaterial k)  = sign h k
  sign h (RSAKeyMaterial k) = sign h k
  sign h (OctKeyMaterial k) = sign h k
  verify JWA.JWS.None _ = \_ s -> Right $ s == ""
  verify h (ECKeyMaterial k)  = verify h k
  verify h (RSAKeyMaterial k) = verify h k
  verify h (OctKeyMaterial k) = verify h k

instance Arbitrary KeyMaterial where
  arbitrary = oneof
    [ ECKeyMaterial <$> arbitrary
    --, RSAKeyMaterial <$> arbitrary
    --, OctKeyMaterial <$> arbitrary
    ]
