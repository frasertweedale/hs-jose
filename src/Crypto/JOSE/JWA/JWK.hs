-- Copyright (C) 2013  Fraser Tweedale
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

module Crypto.JOSE.JWA.JWK where

import Control.Applicative
import Control.Arrow

import Crypto.Hash
import Crypto.PubKey.HashDescr
import Crypto.PubKey.RSA
import qualified Crypto.PubKey.RSA.PKCS15
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


--
-- JWA §5.1.  "kty" (Key Type) Parameter Values
--

$(Crypto.JOSE.TH.deriveJOSEType "EC" ["EC"])    -- Recommended+
$(Crypto.JOSE.TH.deriveJOSEType "RSA" ["RSA"])  -- Required
$(Crypto.JOSE.TH.deriveJOSEType "Oct" ["oct"])  -- Required


--
-- JWA §5.2.1.1.  "crv" (Curve) Parameter
--

$(Crypto.JOSE.TH.deriveJOSEType "Crv" ["P-256", "P-384", "P-521"])


--
-- JWA §5.3.2.7.  "oth" (Other Primes Info) Parameter
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


--
-- JWA §5.3.2.  JWK Parameters for RSA Private Keys
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


--
-- JWA §5.  Cryptographic Algorithms for JWK
--

data ECKeyParameters =
  ECPrivateKeyParameters {
    ecD :: Types.SizedBase64Integer
    }
  | ECPublicKeyParameters {
    ecCrv :: Crv,
    ecX :: Types.SizedBase64Integer,
    ecY :: Types.SizedBase64Integer
    }
  deriving (Eq, Show)

instance FromJSON ECKeyParameters where
  parseJSON = withObject "EC" (\o ->
    ECPrivateKeyParameters    <$> o .: "d"
    <|> ECPublicKeyParameters <$> o .: "crv" <*> o .: "x" <*> o .: "y")

instance ToJSON ECKeyParameters where
  toJSON (ECPrivateKeyParameters d) = object ["d" .= d]
  toJSON (ECPublicKeyParameters {..}) = object [
    "crv" .= ecCrv
    , "x" .= ecX
    , "y" .= ecY
    ]

instance Key ECKeyParameters where
  sign = error "elliptic curve algorithms not implemented"
  verify = error "elliptic curve algorithms not implemented"


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

signRSA :: HashDescr -> RSAKeyParameters -> B.ByteString -> B.ByteString
signRSA h k m = either (error . show) id $
  Crypto.PubKey.RSA.PKCS15.sign Nothing h (privateKey k) m where
    privateKey (RSAPrivateKeyParameters
      (Types.SizedBase64Integer size n)
      (Types.Base64Integer e)
      (Types.Base64Integer d)
      _) = PrivateKey (PublicKey size n e) d 0 0 0 0 0
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
    ) = PublicKey size n e
  publicKey (RSAPublicKeyParameters
    (Types.SizedBase64Integer size n)
    (Types.Base64Integer e)
    ) = PublicKey size n e

genRSAParams :: Int -> IO (RSAKeyParameters, RSAKeyParameters)
genRSAParams size =
  let
    i = Types.Base64Integer
    si = Types.SizedBase64Integer
  in do
    ent <- createEntropyPool
    ((PublicKey s n e, PrivateKey _ d p q dp dq qi), _) <-
      return $ generate (cprgCreate ent :: SystemRNG) size 65537
    return
      ( RSAPublicKeyParameters (si s n) (i e)
      , RSAPrivateKeyParameters (si s n) (i e) (i d)
          (Just (RSAPrivateKeyOptionalParameters
            (i p) (i q) (i dp) (i dq) (i qi) Nothing))
      )

genRSA :: Int -> IO (KeyMaterial, KeyMaterial)
genRSA = fmap (RSAKeyMaterial RSA *** RSAKeyMaterial RSA) . genRSAParams


newtype OctKeyParameters = OctKeyParameters Types.Base64Octets
  deriving (Eq, Show)

instance FromJSON OctKeyParameters where
  parseJSON = (OctKeyParameters <$>) . parseJSON

instance ToJSON OctKeyParameters where
  toJSON (OctKeyParameters k) = toJSON k

instance Key OctKeyParameters where
  sign JWA.JWS.HS256 = signOct SHA256
  sign JWA.JWS.HS384 = signOct SHA384
  sign JWA.JWS.HS512 = signOct SHA512
  sign h = error $ "alg/key mismatch: " ++ show h ++ "/Oct"
  verify h k m s = sign h k m == s

signOct
  :: HashAlgorithm a
  => a
  -> OctKeyParameters
  -> B.ByteString
  -> B.ByteString
signOct a (OctKeyParameters (Types.Base64Octets k)) m = toBytes $ hmacAlg a k m


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
  sign JWA.JWS.None _ = const ""
  sign h (ECKeyMaterial _ k)  = sign h k
  sign h (RSAKeyMaterial _ k) = sign h k
  sign h (OctKeyMaterial _ k) = sign h k
  verify JWA.JWS.None _ = \_ s -> s == ""
  verify h (ECKeyMaterial _ k)  = verify h k
  verify h (RSAKeyMaterial _ k) = verify h k
  verify h (OctKeyMaterial _ k) = verify h k
