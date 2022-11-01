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
{-# LANGUAGE TemplateHaskell #-}

{-|

JSON Web Encryption algorithms.

-}
module Crypto.JOSE.JWA.JWE.Alg
  ( Alg(..)
  ) where

import qualified Crypto.JOSE.TH


-- | RFC 7518 §4.1.  "alg" (Algorithm) Header Parameter Values for JWE
--
-- This section is shuffled off into its own module to avoid
-- circular import via Crypto.JOSE.JWK, which needs Alg.
--
$(Crypto.JOSE.TH.deriveJOSEType "Alg" [
  "RSA1_5"                -- RSAES-PKCS1-V1_5                       Required
  , "RSA-OAEP"            -- RSAES OAEP using default parameters    Optional
  , "RSA-OAEP-256"        -- RSAES OAEP using SHA-256 and MGF1
                          --   with SHA-256                         Optional
  , "A128KW"              -- AES Key Wrap                           Recommended
  , "A192KW"              -- AES Key Wrap                           Optional
  , "A256KW"              -- AES Key Wrap                           Recommended
  , "dir"                 -- direct use of symmetric key            Recommended
  , "ECDH-ES"             -- ECDH Ephemeral Static                  Recommended+
  , "ECDH-ES+A128KW"      --                                        Recommended
  , "ECDH-ES+A192KW"      --                                        Optional
  , "ECDH-ES+A256KW"      --                                        Recommended
  , "A128GCMKW"           -- AES in Galois/Counter Mode             Optional
  , "A192GCMKW"           -- AES in Galois/Counter Mode             Optional
  , "A256GCMKW"           -- AES in Galois/Counter Mode             Optional
  , "PBES2-HS256+A128KW"  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  , "PBES2-HS384+A192KW"  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  , "PBES2-HS512+A256KW"  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  ])
