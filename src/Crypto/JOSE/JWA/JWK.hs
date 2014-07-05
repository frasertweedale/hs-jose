-- Copyright (C) 2013, 2014  Fraser Tweedale
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

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

{-|

Cryptographic Algorithms for Keys.

-}
module Crypto.JOSE.JWA.JWK (
  -- * \"kty\" (Key Type) Parameter Values
    EC(..)
  , RSA(..)
  , Oct(..)

  -- * Parameters for Elliptic Curve Keys
  , ECKeyParameters(..)

  -- * Parameters for RSA Keys
  , RSAPrivateKeyOthElem(..)
  , RSAPrivateKeyOptionalParameters(..)
  , RSAPrivateKeyParameters(..)
  , RSAKeyParameters(..)
  , genRSAParams
  , genRSA

  -- * Parameters for Symmetric Keys
  , OctKeyParameters(..)

  , KeyMaterial(..)
  ) where

import Control.Applicative
import Control.Arrow
import Data.Maybe

import Crypto.Hash
import Crypto.PubKey.HashDescr
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.Types.PubKey.ECC as ECC
import Crypto.Random
import Data.Aeson
import Data.Byteable
import qualified Data.ByteString as B
import qualified Data.HashMap.Strict as M

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
  , rsaOth :: Maybe [RSAPrivateKeyOthElem] -- TODO oth must not be empty array
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
  parseJSON = withObject "EC" $ \o -> ECKeyParameters
    <$> o .: "kty"
    <*> o .: "crv"
    <*> o .: "x"
    <*> o .: "y"
    <*> o .:? "d"

instance ToJSON ECKeyParameters where
  toJSON (ECKeyParameters {..}) = object $
    [ "crv" .= ecCrv
    , "x" .= ecX
    , "y" .= ecY
    ] ++ fmap ("d" .=) (maybeToList ecD)

instance Key ECKeyParameters where
  sign JWA.JWS.ES256 k@(ECKeyParameters { ecCrv = P_256 }) =
    signEC hashDescrSHA256 k
  sign JWA.JWS.ES384 k@(ECKeyParameters { ecCrv = P_384 }) =
    signEC hashDescrSHA384 k
  sign JWA.JWS.ES512 k@(ECKeyParameters { ecCrv = P_521 }) =
    signEC hashDescrSHA512 k
  sign h _ = \g _ ->
    (Left $ AlgorithmMismatch  $ show h ++ "cannot be used with EC key", g)
  verify JWA.JWS.ES256 = verifyEC hashDescrSHA256
  verify JWA.JWS.ES384 = verifyEC hashDescrSHA384
  verify JWA.JWS.ES512 = verifyEC hashDescrSHA512
  verify h = \_ _ _ ->
    Left $ AlgorithmMismatch  $ show h ++ "cannot be used with EC key"

signEC
  :: CPRG g
  => HashDescr
  -> ECKeyParameters
  -> g
  -> B.ByteString
  -> (Either Error B.ByteString, g)
signEC h k@(ECKeyParameters {..}) g m = case ecD of
  Just ecD' -> first (Right . sigToBS) sig where
    sig = ECDSA.sign g privateKey (hashFunction h) m
    sigToBS (ECDSA.Signature r s) =
      Types.integerToBS r `B.append` Types.integerToBS s
    privateKey = ECDSA.PrivateKey (curve k) (d ecD')
    d (Types.SizedBase64Integer _ n) = n
  Nothing -> (Left $ KeyMismatch "not an EC private key", g)

verifyEC
  :: HashDescr
  -> ECKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Either Error Bool
verifyEC h k m s = Right $ ECDSA.verify (hashFunction h) pubkey sig m
  where
  pubkey = ECDSA.PublicKey (curve k) (point k)
  sig = uncurry ECDSA.Signature
    $ Types.bsToInteger *** Types.bsToInteger
    $ B.splitAt (B.length s `div` 2) s

curve :: ECKeyParameters -> ECC.Curve
curve ECKeyParameters {..} = ECC.getCurveByName (curveName ecCrv) where
  curveName P_256 = ECC.SEC_p256r1
  curveName P_384 = ECC.SEC_p384r1
  curveName P_521 = ECC.SEC_p521r1

point :: ECKeyParameters -> ECC.Point
point ECKeyParameters {..} = ECC.Point (integer ecX) (integer ecY) where
  integer (Types.SizedBase64Integer _ n) = n


-- | Parameters for RSA Keys
--
data RSAKeyParameters = RSAKeyParameters
  { rsaKty :: RSA
  , rsaN :: Types.SizedBase64Integer
  , rsaE :: Types.Base64Integer
  , rsaPrivateKeyParameters :: Maybe RSAPrivateKeyParameters
  }
  deriving (Eq, Show)

instance FromJSON RSAKeyParameters where
  parseJSON = withObject "RSA" $ \o ->
    RSAKeyParameters
      <$> o .: "kty"
      <*> o .: "n"
      <*> o .: "e"
      <*> parseJSON (Object o)

instance ToJSON RSAKeyParameters where
  toJSON RSAKeyParameters {..} = object $
      ("kty" .= rsaKty)
    : ("n" .= rsaN)
    : ("e" .= rsaE)
    : maybe [] (Types.objectPairs . toJSON) rsaPrivateKeyParameters

instance Key RSAKeyParameters where
  sign JWA.JWS.RS256 = signPKCS15 hashDescrSHA256
  sign JWA.JWS.RS384 = signPKCS15 hashDescrSHA384
  sign JWA.JWS.RS512 = signPKCS15 hashDescrSHA512
  sign JWA.JWS.PS256 = signPSS hashDescrSHA256
  sign JWA.JWS.PS384 = signPSS hashDescrSHA384
  sign JWA.JWS.PS512 = signPSS hashDescrSHA512
  sign h = \_ g -> const
    (Left $ AlgorithmMismatch  $ show h ++ "cannot be used with RSA key", g)
  verify JWA.JWS.RS256 = verifyPKCS15 hashDescrSHA256
  verify JWA.JWS.RS384 = verifyPKCS15 hashDescrSHA384
  verify JWA.JWS.RS512 = verifyPKCS15 hashDescrSHA512
  verify JWA.JWS.PS256 = verifyPSS hashDescrSHA256
  verify JWA.JWS.PS384 = verifyPSS hashDescrSHA384
  verify JWA.JWS.PS512 = verifyPSS hashDescrSHA512
  verify h = \_ _ _ ->
    Left $ AlgorithmMismatch  $ show h ++ "cannot be used with RSA key"

signPKCS15
  :: CPRG g
  => HashDescr
  -> RSAKeyParameters
  -> g
  -> B.ByteString
  -> (Either Error B.ByteString, g)
signPKCS15 h k g m = case rsaPrivateKey k of
  Left e -> (Left e, g)
  Right k' -> first (either (Left . RSAError) Right) $
    PKCS15.signSafer g h k' m

verifyPKCS15
  :: HashDescr
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Either Error Bool
verifyPKCS15 h k m = Right . PKCS15.verify h (rsaPublicKey k) m

signPSS
  :: CPRG g
  => HashDescr
  -> RSAKeyParameters
  -> g
  -> B.ByteString
  -> (Either Error B.ByteString, g)
signPSS h k g m = case rsaPrivateKey k of
  Left e -> (Left e, g)
  Right k' -> first (either (Left . RSAError) Right) $
   PSS.signSafer g (PSS.defaultPSSParams (hashFunction h)) k' m

verifyPSS
  :: HashDescr
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Either Error Bool
verifyPSS h k m = Right .
  PSS.verify (PSS.defaultPSSParams (hashFunction h)) (rsaPublicKey k) m

rsaPrivateKey :: RSAKeyParameters -> Either Error RSA.PrivateKey
rsaPrivateKey (RSAKeyParameters _
  (Types.SizedBase64Integer size n)
  (Types.Base64Integer e)
  (Just (RSAPrivateKeyParameters (Types.Base64Integer d) _)))
  | size >= 2048 `div` 8 = Right $
    RSA.PrivateKey (RSA.PublicKey size n e) d 0 0 0 0 0
  | otherwise = Left KeySizeTooSmall
rsaPrivateKey _ = Left $ KeyMismatch "not an RSA private key"

rsaPublicKey :: RSAKeyParameters -> RSA.PublicKey
rsaPublicKey (RSAKeyParameters _
  (Types.SizedBase64Integer size n) (Types.Base64Integer e) _)
  = RSA.PublicKey size n e


-- | Generate RSA public and private key parameters.
--
genRSAParams :: Int -> IO RSAKeyParameters
genRSAParams size =
  let
    i = Types.Base64Integer
    si = Types.SizedBase64Integer
  in do
    ent <- createEntropyPool
    ((RSA.PublicKey s n e, RSA.PrivateKey _ d p q dp dq qi), _) <-
      return $ RSA.generate (cprgCreate ent :: SystemRNG) size 65537
    return $
      RSAKeyParameters RSA (si s n) (i e) $
        Just (RSAPrivateKeyParameters (i d)
          (Just (RSAPrivateKeyOptionalParameters
            (i p) (i q) (i dp) (i dq) (i qi) Nothing)))

-- | Generate RSA public and private key material.
--
genRSA :: Int -> IO KeyMaterial
genRSA = fmap RSAKeyMaterial . genRSAParams


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
  sign JWA.JWS.HS256 k g = first Right . (,g) . signOct SHA256 k
  sign JWA.JWS.HS384 k g = first Right . (,g) . signOct SHA384 k
  sign JWA.JWS.HS512 k g = first Right . (,g) . signOct SHA512 k
  sign h _ g = const
    (Left $ AlgorithmMismatch $ show h ++ "cannot be used with Oct key", g)
  verify h k m s = fst (sign h k (undefined :: SystemRNG) m) >>= Right . (== s)

signOct
  :: HashAlgorithm a
  => a
  -> OctKeyParameters
  -> B.ByteString
  -> B.ByteString
signOct a (OctKeyParameters _ (Types.Base64Octets k)) m
  = toBytes $ hmacAlg a k m


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

instance Key KeyMaterial where
  sign JWA.JWS.None _ = \g _ -> (Right "", g)
  sign h (ECKeyMaterial k)  = sign h k
  sign h (RSAKeyMaterial k) = sign h k
  sign h (OctKeyMaterial k) = sign h k
  verify JWA.JWS.None _ = \_ s -> Right $ s == ""
  verify h (ECKeyMaterial k)  = verify h k
  verify h (RSAKeyMaterial k) = verify h k
  verify h (OctKeyMaterial k) = verify h k
