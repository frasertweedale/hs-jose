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
  , RSAKeyParameters(..)
  , genRSAParams
  , genRSA

  -- * Parameters for Symmetric Keys
  , OctKeyParameters(..)

  , KeyMaterial(..)
  ) where

import Control.Applicative
import Control.Arrow

import Crypto.Hash
import Crypto.PubKey.HashDescr
import qualified Crypto.PubKey.ECC.ECDSA
import qualified Crypto.PubKey.RSA
import qualified Crypto.PubKey.RSA.PKCS15
import qualified Crypto.Types.PubKey.ECC
import qualified Crypto.Types.PubKey.ECDSA
import Crypto.Random
import Data.Aeson
import Data.Byteable
import qualified Data.ByteString as B
import qualified Data.HashMap.Strict as M

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
    , "dq" .= rsaQi
    ] ++ maybe [] ((:[]) . ("oth" .=)) rsaOth


-- | Parameters for Elliptic Curve Keys
--
data ECKeyParameters =
  ECPrivateKeyParameters
    { ecCrv :: Crv
    , ecX :: Types.SizedBase64Integer
    , ecY :: Types.SizedBase64Integer
    , ecD :: Types.SizedBase64Integer
    }
  | ECPublicKeyParameters
    { ecCrv' :: Crv
    , ecX' :: Types.SizedBase64Integer
    , ecY' :: Types.SizedBase64Integer
    }
  deriving (Eq, Show)

instance FromJSON ECKeyParameters where
  parseJSON = withObject "EC" $ \o ->
    ECPrivateKeyParameters
      <$> o .: "crv"
      <*> o .: "x"
      <*> o .: "y"
      <*> o .: "d"
    <|> ECPublicKeyParameters
      <$> o .: "crv"
      <*> o .: "x"
      <*> o .: "y"

instance ToJSON ECKeyParameters where
  toJSON (ECPrivateKeyParameters {..}) = object
    [ "crv" .= ecCrv
    , "x" .= ecX
    , "y" .= ecY
    , "d" .= ecD
    ]
  toJSON (ECPublicKeyParameters {..}) = object
    [ "crv" .= ecCrv'
    , "x" .= ecX'
    , "y" .= ecY'
    ]

instance Key ECKeyParameters where
  sign JWA.JWS.ES256 k@(ECPrivateKeyParameters { ecCrv = P_256 }) =
    signEC hashDescrSHA256 k
  sign JWA.JWS.ES384 k@(ECPrivateKeyParameters { ecCrv = P_384 }) =
    signEC hashDescrSHA384 k
  sign JWA.JWS.ES512 k@(ECPrivateKeyParameters { ecCrv = P_521 }) =
    signEC hashDescrSHA512 k
  sign h _ = error $ "alg/key mismatch: " ++ show h ++ "/ECDSA"
  verify JWA.JWS.ES256 = verifyEC hashDescrSHA256
  verify JWA.JWS.ES384 = verifyEC hashDescrSHA384
  verify JWA.JWS.ES512 = verifyEC hashDescrSHA512
  verify h = error $ "alg/key mismatch: " ++ show h ++ "/ECDSA"

signEC
  :: CPRG g
  => HashDescr
  -> ECKeyParameters
  -> g
  -> B.ByteString
  -> (B.ByteString, g)
signEC h k@(ECPrivateKeyParameters {..}) g m = first sigToBS sig where
  sig = Crypto.PubKey.ECC.ECDSA.sign g privateKey (hashFunction h) m
  sigToBS (Crypto.Types.PubKey.ECDSA.Signature r s) =
    Types.integerToBS r `B.append` Types.integerToBS s
  privateKey = Crypto.Types.PubKey.ECDSA.PrivateKey (curve k) (d ecD)
  d (Types.SizedBase64Integer _ n) = n
signEC _ _ _ _ = error "not a private key"

verifyEC
  :: HashDescr
  -> ECKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Bool
verifyEC h k m s = Crypto.PubKey.ECC.ECDSA.verify (hashFunction h) pubkey sig m
  where
    pubkey = Crypto.Types.PubKey.ECDSA.PublicKey (curve k) (point k)
    sig = uncurry Crypto.Types.PubKey.ECDSA.Signature
      $ Types.bsToInteger *** Types.bsToInteger
      $ B.splitAt (B.length s `div` 2) s

curve :: ECKeyParameters -> Crypto.Types.PubKey.ECC.Curve
curve k = case k of
 ECPrivateKeyParameters {..} -> curve' ecCrv
 ECPublicKeyParameters {..} -> curve' ecCrv'
 where
  curve' c = Crypto.Types.PubKey.ECC.getCurveByName (curveName c)
  curveName P_256 = Crypto.Types.PubKey.ECC.SEC_p256r1
  curveName P_384 = Crypto.Types.PubKey.ECC.SEC_p384r1
  curveName P_521 = Crypto.Types.PubKey.ECC.SEC_p521r1

point :: ECKeyParameters -> Crypto.Types.PubKey.ECC.Point
point k = case k of
 ECPrivateKeyParameters {..} -> point' ecX ecY
 ECPublicKeyParameters {..} -> point' ecX' ecY'
 where
  point' x y = Crypto.Types.PubKey.ECC.Point (integer x) (integer y)
  integer (Types.SizedBase64Integer _ n) = n



-- | Parameters for RSA Keys
--
data RSAKeyParameters =
  RSAPrivateKeyParameters {
    rsaN :: Types.SizedBase64Integer
    , rsaE :: Types.Base64Integer
    , rsaD :: Types.Base64Integer
    , rsaOptionalParameters :: Maybe RSAPrivateKeyOptionalParameters
    }
  | RSAPublicKeyParameters {
    rsaN' :: Types.SizedBase64Integer
    , rsaE' :: Types.Base64Integer
    }
  deriving (Eq, Show)

instance FromJSON RSAKeyParameters where
  parseJSON = withObject "RSA" (\o ->
    RSAPrivateKeyParameters
      <$> o .: "n"
      <*> o .: "e"
      <*> o .: "d"
      <*> (if any (`M.member` o) ["p", "q", "dp", "dq", "qi", "oth"]
        then Just <$> parseJSON (Object o)
        else pure Nothing)
    <|> RSAPublicKeyParameters <$> o .: "n" <*> o .: "e")

instance ToJSON RSAKeyParameters where
  toJSON (RSAPrivateKeyParameters {..}) = object $
    ("n" .= rsaN)
    : ("e" .= rsaE)
    : ("d" .= rsaD)
    : maybe [] (Types.objectPairs . toJSON) rsaOptionalParameters
  toJSON (RSAPublicKeyParameters n e) = object ["n" .= n, "e" .= e]

instance Key RSAKeyParameters where
  sign JWA.JWS.RS256 = signRSA hashDescrSHA256
  sign JWA.JWS.RS384 = signRSA hashDescrSHA384
  sign JWA.JWS.RS512 = signRSA hashDescrSHA512
  sign h = error $ "alg/key mismatch: " ++ show h ++ "/RSA"
  verify JWA.JWS.RS256 = verifyRSA hashDescrSHA256
  verify JWA.JWS.RS384 = verifyRSA hashDescrSHA384
  verify JWA.JWS.RS512 = verifyRSA hashDescrSHA512
  verify h = error $ "alg/key mismatch: " ++ show h ++ "/RSA"

signRSA
  :: CPRG g
  => HashDescr
  -> RSAKeyParameters
  -> g
  -> B.ByteString
  -> (B.ByteString, g)
signRSA h k g m = first (either (error . show) id) $
  Crypto.PubKey.RSA.PKCS15.signSafer g h (privateKey k) m where
    privateKey (RSAPrivateKeyParameters
      (Types.SizedBase64Integer size n)
      (Types.Base64Integer e)
      (Types.Base64Integer d)
      _) = Crypto.PubKey.RSA.PrivateKey
        (Crypto.PubKey.RSA.PublicKey size n e) d 0 0 0 0 0
    privateKey _ = error "not an RSA private key"

verifyRSA
  :: HashDescr
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Bool
verifyRSA h k = Crypto.PubKey.RSA.PKCS15.verify h (publicKey k) where
  publicKey (RSAPrivateKeyParameters
    (Types.SizedBase64Integer size n)
    (Types.Base64Integer e)
    _
    _
    ) = Crypto.PubKey.RSA.PublicKey size n e
  publicKey (RSAPublicKeyParameters
    (Types.SizedBase64Integer size n)
    (Types.Base64Integer e)
    ) = Crypto.PubKey.RSA.PublicKey size n e

-- | Generate RSA public and private key parameters.
--
genRSAParams :: Int -> IO (RSAKeyParameters, RSAKeyParameters)
genRSAParams size =
  let
    i = Types.Base64Integer
    si = Types.SizedBase64Integer
  in do
    ent <- createEntropyPool
    ((Crypto.PubKey.RSA.PublicKey s n e, Crypto.PubKey.RSA.PrivateKey _ d p q dp dq qi), _) <-
      return $ Crypto.PubKey.RSA.generate (cprgCreate ent :: SystemRNG) size 65537
    return
      ( RSAPublicKeyParameters (si s n) (i e)
      , RSAPrivateKeyParameters (si s n) (i e) (i d)
          (Just (RSAPrivateKeyOptionalParameters
            (i p) (i q) (i dp) (i dq) (i qi) Nothing))
      )

-- | Generate RSA public and private key material.
--
genRSA :: Int -> IO (KeyMaterial, KeyMaterial)
genRSA = fmap (RSAKeyMaterial RSA *** RSAKeyMaterial RSA) . genRSAParams


-- | Symmetric key parameters data.
--
newtype OctKeyParameters = OctKeyParameters Types.Base64Octets
  deriving (Eq, Show)

instance FromJSON OctKeyParameters where
  parseJSON = (OctKeyParameters <$>) . parseJSON

instance ToJSON OctKeyParameters where
  toJSON (OctKeyParameters k) = toJSON k

instance Key OctKeyParameters where
  sign JWA.JWS.HS256 k g = (,g) . signOct SHA256 k
  sign JWA.JWS.HS384 k g = (,g) . signOct SHA384 k
  sign JWA.JWS.HS512 k g = (,g) . signOct SHA512 k
  sign h _ _ = error $ "alg/key mismatch: " ++ show h ++ "/Oct"
  verify h k m s = fst (sign h k (undefined :: SystemRNG) m) == s

signOct
  :: HashAlgorithm a
  => a
  -> OctKeyParameters
  -> B.ByteString
  -> B.ByteString
signOct a (OctKeyParameters (Types.Base64Octets k)) m = toBytes $ hmacAlg a k m


-- | Key material sum type.
--
data KeyMaterial =
  ECKeyMaterial EC ECKeyParameters
  | RSAKeyMaterial RSA RSAKeyParameters
  | OctKeyMaterial Oct OctKeyParameters
  deriving (Eq, Show)

instance FromJSON KeyMaterial where
  parseJSON = withObject "KeyMaterial" (\o ->
    ECKeyMaterial      <$> o .: "kty" <*> parseJSON (Object o)
    <|> RSAKeyMaterial <$> o .: "kty" <*> parseJSON (Object o)
    <|> OctKeyMaterial <$> o .: "kty" <*> o .: "k")

instance ToJSON KeyMaterial where
  toJSON (ECKeyMaterial k p)  = object $ ("kty" .= k) : Types.objectPairs (toJSON p)
  toJSON (RSAKeyMaterial k p) = object $ ("kty" .= k) : Types.objectPairs (toJSON p)
  toJSON (OctKeyMaterial k i) = object ["kty" .= k, "k" .= i]

instance Key KeyMaterial where
  sign JWA.JWS.None _ = \g _ -> ("", g)
  sign h (ECKeyMaterial _ k)  = sign h k
  sign h (RSAKeyMaterial _ k) = sign h k
  sign h (OctKeyMaterial _ k) = sign h k
  verify JWA.JWS.None _ = \_ s -> s == ""
  verify h (ECKeyMaterial _ k)  = verify h k
  verify h (RSAKeyMaterial _ k) = verify h k
  verify h (OctKeyMaterial _ k) = verify h k
