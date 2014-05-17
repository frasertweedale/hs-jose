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

module Crypto.JOSE.JWA.JWE where

import Crypto.JOSE.JWK
import Crypto.JOSE.TH
import Crypto.JOSE.Types


--
-- JWA §4.  Cryptographic Algorithms for Encryption
--

--
-- JWA 4.1.  "alg" (Algorithms) Header Parameter Values for JWE

data JWEAlgHeaderParameters =
  -- JWA §4.7.1.  Header Parameters Used for ECDH Key Agreement
  ECDHParameters {
    epk :: JWK,   -- Ephemeral Public Key ; a JWK PUBLIC key
    apu :: Maybe Base64UrlString, -- Agreement PartyUInfo
    apv :: Maybe Base64UrlString  -- Agreement PartyVInfo
    }
  -- JWA §4.8.1.  Header Parameters Used for AES GCM Key Encryption
  | AESGCMParameters {
    iv :: Base64Octets, -- Initialization Vector
    tag :: Base64Octets -- Authentication Tag
    }
  -- JWA §4.9.1.  Header Parameters Used for PBES2 Key Encryption
  | PBES2Parameters {
    p2s :: Base64Octets,  -- PBKDF2 salt value
    p2c :: Int                  -- PBKDF2 iteration count ; POSITIVE integer
    }
  deriving (Show)


--
-- JWA §4.2.  "enc" (Encryption Method) Header Parameters Values for JWE
--

$(deriveJOSEType "Enc" [
  "A128CBC-HS256"   -- AES HMAC SHA authenticated encryption  Required
  , "A192CBC-HS384" -- AES HMAC SHA authenticated encryption  Optional
  , "A256CBC-HS512" -- AES HMAC SHA authenticated encryption  Required
  , "A128GCM"       -- AES in Galois/Counter Mode             Recommended
  , "A192GCM"       -- AES in Galois/Counter Mode             Optional
  , "A256GCM"       -- AES in Galois/Counter Mode             Recommended
  ])
