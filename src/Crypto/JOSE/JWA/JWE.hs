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
module Crypto.JOSE.JWA.JWE where

import Data.Maybe (catMaybes)

import qualified Data.HashMap.Strict as M

import Crypto.JOSE.JWK
import Crypto.JOSE.TH
import Crypto.JOSE.Types
import Crypto.JOSE.Types.Internal (insertToObject)

import Data.Aeson


-- | RFC 7518 §4.  Cryptographic Algorithms for Key Management
--
data AlgWithParams
  = RSA1_5
  | RSA_OAEP
  | RSA_OAEP_256
  | A128KW
  | A192KW
  | A256KW
  | Dir
  | ECDH_ES ECDHParameters
  | ECDH_ES_A128KW ECDHParameters
  | ECDH_ES_A192KW ECDHParameters
  | ECDH_ES_A256KW ECDHParameters
  | A128GCMKW AESGCMParameters
  | A192GCMKW AESGCMParameters
  | A256GCMKW AESGCMParameters
  | PBES2_HS256_A128KW PBES2Parameters
  | PBES2_HS384_A192KW PBES2Parameters
  | PBES2_HS512_A256KW PBES2Parameters
  deriving (Eq, Show)

instance FromJSON AlgWithParams where
  parseJSON = withObject "Encryption alg and params" $ \o ->
    case M.lookup "alg" o of
      Nothing -> fail "\"alg\" parameter is required"
      Just "RSA1_5"             -> pure RSA1_5
      Just "RSA-OAEP"           -> pure RSA_OAEP
      Just "RSA-OAEP-256"       -> pure RSA_OAEP_256
      Just "A128KW"             -> pure A128KW
      Just "A192KW"             -> pure A192KW
      Just "A256KW"             -> pure A256KW
      Just "dir"                -> pure Dir
      Just "ECDH-ES"            -> ECDH_ES            <$> parseJSON (Object o)
      Just "ECDH-ES+A128KW"     -> ECDH_ES_A128KW     <$> parseJSON (Object o)
      Just "ECDH-ES+A192KW"     -> ECDH_ES_A192KW     <$> parseJSON (Object o)
      Just "ECDH-ES+A256KW"     -> ECDH_ES_A256KW     <$> parseJSON (Object o)
      Just "A128GCMKW"          -> A128GCMKW          <$> parseJSON (Object o)
      Just "A192GCMKW"          -> A192GCMKW          <$> parseJSON (Object o)
      Just "A256GCMKW"          -> A256GCMKW          <$> parseJSON (Object o)
      Just "PBES2-HS256+A128KW" -> PBES2_HS256_A128KW <$> parseJSON (Object o)
      Just "PBES2-HS384+A192KW" -> PBES2_HS384_A192KW <$> parseJSON (Object o)
      Just "PBES2-HS512+A256KW" -> PBES2_HS512_A256KW <$> parseJSON (Object o)
      _ -> fail $ "unrecognised value; expected: "
         ++ "[\"RSA1_5\",\"RSA-OAEP\",\"RSA-OAEP-256\",\"A128KW\",\"A192KW\",\"A256KW\",\"dir\",\"ECDH-ES\",\"ECDH-ES+A128KW\",\"ECDH-ES+A192KW\",\"ECDH-ES+A256KW\",\"A128GCMKW\",\"A192GCMKW\",\"A256GCMKW\",\"PBES2-HS256+A128KW\",\"PBES2-HS384+A128KW\",\"PBES2-HS512+A128KW\"]"

algObject :: Value -> Value
algObject s = object [("alg", s)]

algWithParamsObject :: ToJSON a => a -> Value -> Value
algWithParamsObject a s = insertToObject "alg" s (toJSON a)

instance ToJSON AlgWithParams where
  toJSON RSA1_5       = algObject "RSA1_5"
  toJSON RSA_OAEP     = algObject "RSA-OAEP"
  toJSON RSA_OAEP_256 = algObject "RSA-OAEP-256"
  toJSON A128KW       = algObject "A128KW"
  toJSON A192KW       = algObject "A192KW"
  toJSON A256KW       = algObject "A256KW"
  toJSON Dir          = algObject "Dir"
  toJSON (ECDH_ES params)             = algWithParamsObject params "ECDH-ES"
  toJSON (ECDH_ES_A128KW params)      = algWithParamsObject params "ECDH-ES+A128KW"
  toJSON (ECDH_ES_A192KW params)      = algWithParamsObject params "ECDH-ES+A192KW"
  toJSON (ECDH_ES_A256KW params)      = algWithParamsObject params "ECDH-ES+A256KW"
  toJSON (A128GCMKW params)           = algWithParamsObject params "A128GCMKW"
  toJSON (A192GCMKW params)           = algWithParamsObject params "A192GCMKW"
  toJSON (A256GCMKW params)           = algWithParamsObject params "A256GCMKW"
  toJSON (PBES2_HS256_A128KW params)  = algWithParamsObject params "PBES2-HS256+A128KW"
  toJSON (PBES2_HS384_A192KW params)  = algWithParamsObject params "PBES2-HS384+A192KW"
  toJSON (PBES2_HS512_A256KW params)  = algWithParamsObject params "PBES2-HS512+A256KW"


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
    , fmap ("apu" .=) apv
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
