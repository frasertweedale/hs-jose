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
{-# LANGUAGE TemplateHaskell #-}

{-|

JSON Web Encryption data types specified under JSON Web Algorithms.

-}
module Crypto.JOSE.JWA.JWE
  ( Enc(..)
  , AlgWithParams(..)
  , AlgOnly(..)
  , SimpleAlg(..)
  , ECDHESAlg(..)
  , AESGCMAlg(..)
  , PBES2Alg(..)
  , algType
  , algOnly
  , knownAlgsMsg
  , AESGCMParameters(AESGCMParameters)
  , ECDHParameters(ECDHParameters)
  , PBES2Parameters(PBES2Parameters)
  ) where

import Data.Maybe (catMaybes)

import Crypto.JOSE.JWK
import Crypto.JOSE.TH
import Crypto.JOSE.Types
import Crypto.JOSE.Types.Internal (insertToObject)

import Data.Aeson
import qualified Data.Aeson.KeyMap as M
import qualified Data.Text as Text


-- | RFC 7518 §4.  Cryptographic Algorithms for Key Management
--
data SimpleAlg
  = RSA1_5
  | RSA_OAEP
  | RSA_OAEP_256
  | A128KW
  | A192KW
  | A256KW
  | Dir
  deriving (Eq, Show)

data ECDHESAlg
  = ECDH_ES
  | ECDH_ES_A128KW
  | ECDH_ES_A192KW
  | ECDH_ES_A256KW
  deriving (Eq, Show)

data AESGCMAlg
  = A128GCMKW
  | A192GCMKW
  | A256GCMKW
  deriving (Eq, Show)

data PBES2Alg
  = PBES2_HS256_A128KW
  | PBES2_HS384_A192KW
  | PBES2_HS512_A256KW
  deriving (Eq, Show)

data AlgWithParams
  = SimpleAlg SimpleAlg
  | ECDHESAlg ECDHESAlg ECDHParameters
  | AESGCMAlg AESGCMAlg AESGCMParameters
  | PBES2Alg PBES2Alg PBES2Parameters
  deriving (Eq, Show)

data AlgOnly
  = SimpleAlgOnly SimpleAlg
  | ECDHESAlgOnly ECDHESAlg
  | AESGCMAlgOnly AESGCMAlg
  | PBES2AlgOnly PBES2Alg
  deriving (Eq, Show)

algType :: Text.Text -> Either () AlgOnly
algType t = case t of
  "RSA1_5"             -> simple RSA1_5
  "RSA-OAEP"           -> simple RSA_OAEP
  "RSA-OAEP-256"       -> simple RSA_OAEP_256
  "A128KW"             -> simple A128KW
  "A192KW"             -> simple A192KW
  "A256KW"             -> simple A256KW
  "dir"                -> simple Dir
  "ECDH-ES"            -> ecdh ECDH_ES
  "ECDH-ES+A128KW"     -> ecdh ECDH_ES_A128KW
  "ECDH-ES+A192KW"     -> ecdh ECDH_ES_A192KW
  "ECDH-ES+A256KW"     -> ecdh ECDH_ES_A256KW
  "A128GCMKW"          -> aesgcm A128GCMKW
  "A192GCMKW"          -> aesgcm A192GCMKW
  "A256GCMKW"          -> aesgcm A256GCMKW
  "PBES2-HS256+A128KW" -> pbes2 PBES2_HS256_A128KW
  "PBES2-HS384+A192KW" -> pbes2 PBES2_HS384_A192KW
  "PBES2-HS512+A256KW" -> pbes2 PBES2_HS512_A256KW
  _                    -> Left ()
  where
    simple = pure . SimpleAlgOnly
    ecdh = pure . ECDHESAlgOnly
    aesgcm = pure . AESGCMAlgOnly
    pbes2 = pure . PBES2AlgOnly

algOnly :: AlgWithParams -> AlgOnly
algOnly (SimpleAlg a) = SimpleAlgOnly a
algOnly (ECDHESAlg a _) = ECDHESAlgOnly a
algOnly (AESGCMAlg a _) = AESGCMAlgOnly a
algOnly (PBES2Alg a _) = PBES2AlgOnly a

instance FromJSON AlgWithParams where
  parseJSON = withObject "Encryption alg and params" $ \o ->
    case algType . (\x -> case x of String t -> t ; _ -> "") <$> M.lookup "alg" o of
      Nothing -> fail "\"alg\" parameter is required"
      Just (Right (SimpleAlgOnly a)) -> pure $ SimpleAlg a
      Just (Right (ECDHESAlgOnly a)) -> ECDHESAlg a <$> parseJSON (Object o)
      Just (Right (AESGCMAlgOnly a)) -> AESGCMAlg a <$> parseJSON (Object o)
      Just (Right (PBES2AlgOnly a))  -> PBES2Alg a <$> parseJSON (Object o)
      _ -> fail $ "unrecognised value; expected: " ++ knownAlgsMsg

knownAlgsMsg :: String
knownAlgsMsg = "[\"RSA1_5\",\"RSA-OAEP\",\"RSA-OAEP-256\",\"A128KW\",\"A192KW\",\"A256KW\",\"dir\",\"ECDH-ES\",\"ECDH-ES+A128KW\",\"ECDH-ES+A192KW\",\"ECDH-ES+A256KW\",\"A128GCMKW\",\"A192GCMKW\",\"A256GCMKW\",\"PBES2-HS256+A128KW\",\"PBES2-HS384+A128KW\",\"PBES2-HS512+A128KW\"]"

algObject :: Value -> Value
algObject s = object [("alg", s)]

algWithParamsObject :: ToJSON a => a -> Value -> Value
algWithParamsObject a s = insertToObject "alg" s (toJSON a)

instance ToJSON AlgWithParams where
  toJSON (SimpleAlg a) = algObject $ case a of
    RSA1_5       -> "RSA1_5"
    RSA_OAEP     -> "RSA-OAEP"
    RSA_OAEP_256 -> "RSA-OAEP-256"
    A128KW       -> "A128KW"
    A192KW       -> "A192KW"
    A256KW       -> "A256KW"
    Dir          -> "dir"
  toJSON (ECDHESAlg a params) = algWithParamsObject params $ case a of
    ECDH_ES        -> "ECDH-ES"
    ECDH_ES_A128KW -> "ECDH-ES+A128KW"
    ECDH_ES_A192KW -> "ECDH-ES+A192KW"
    ECDH_ES_A256KW -> "ECDH-ES+A256KW"
  toJSON (AESGCMAlg a params) = algWithParamsObject params $ case a of
    A128GCMKW -> "A128GCMKW"
    A192GCMKW -> "A192GCMKW"
    A256GCMKW -> "A256GCMKW"
  toJSON (PBES2Alg a params) = algWithParamsObject params $ case a of
    PBES2_HS256_A128KW -> "PBES2-HS256+A128KW"
    PBES2_HS384_A192KW -> "PBES2-HS384+A192KW"
    PBES2_HS512_A256KW -> "PBES2-HS512+A256KW"


-- | RFC 7518 §4.6.1.  Header Parameters Used for ECDH Key Agreement
--
data ECDHParameters = ECDHParameters
  { _epk :: JWK                 -- ^ Ephemeral Public Key ; a JWK PUBLIC key
  , _apu :: Maybe Base64Octets  -- ^ Agreement PartyUInfo
  , _apv :: Maybe Base64Octets  -- ^ Agreement PartyVInfo
  } deriving (Eq, Show)

instance FromJSON ECDHParameters where
  parseJSON = withObject "ECDH Parameters" $ \o -> ECDHParameters
    <$> o .: "epk"
    <*> o .:? "apu"
    <*> o .:? "apv"

instance ToJSON ECDHParameters where
  toJSON (ECDHParameters epk apu apv) = object $ catMaybes
    [ Just ("epk" .= epk)
    , fmap ("apu" .=) apu
    , fmap ("apv" .=) apv
    ]


-- | RFC 7518 §4.7.1.  Header Parameters Used for AES GCM Key Encryption
--
data AESGCMParameters = AESGCMParameters
  { _iv :: Base64Octets  -- ^ Initialization Vector  (must be 96 bits?)
  , _tag :: Base64Octets -- ^ Authentication Tag (must be 128 bits?)
  } deriving (Eq, Show)

instance FromJSON AESGCMParameters where
  parseJSON = withObject "AES-GCM Parameters" $ \o -> AESGCMParameters
    <$> o .: "iv"
    <*> o .: "tag"

instance ToJSON AESGCMParameters where
  toJSON (AESGCMParameters iv tag) = object ["iv" .= iv, "tag" .= tag]


-- | RFC 7518 §4.8.1.  Header Parameters Used for PBES2 Key Encryption
--
data PBES2Parameters =  PBES2Parameters
  { _p2s :: Base64Octets   -- ^ PBKDF2 salt input
  , _p2c :: Int            -- ^ PBKDF2 iteration count ; POSITIVE integer
  } deriving (Eq, Show)

instance FromJSON PBES2Parameters where
  parseJSON = withObject "AES-GCM Parameters" $ \o -> PBES2Parameters
    <$> o .: "p2s"  -- TODO salt input value must be >= 8 octets
    <*> o .: "p2c"

instance ToJSON PBES2Parameters where
  toJSON (PBES2Parameters p2s p2c) = object ["p2s" .= p2s, "p2c" .= p2c]


-- | RFC 7518 §5  Cryptographic Algorithms for Content Encryption
--
$(deriveJOSEType "Enc" [
  "A128CBC-HS256"   -- AES HMAC SHA authenticated encryption  Required
  , "A192CBC-HS384" -- AES HMAC SHA authenticated encryption  Optional
  , "A256CBC-HS512" -- AES HMAC SHA authenticated encryption  Required
  , "A128GCM"       -- AES in Galois/Counter Mode             Recommended
  , "A192GCM"       -- AES in Galois/Counter Mode             Optional
  , "A256GCM"       -- AES in Galois/Counter Mode             Recommended
  ])
