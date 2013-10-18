-- This file is part of jose - web crypto library
-- Copyright (C) 2013  Fraser Tweedale
--
-- jose is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Crypto.JOSE.JWA.JWE.Alg where

import qualified Crypto.JOSE.TH


--
-- JWA §4.1.  "alg" (Algorithm) Header Parameter Values for JWE
--
-- This section is shuffled off into its own module to avoid
-- circular import via Crypto.JOSE.JWK, which needs Alg.
--

$(Crypto.JOSE.TH.deriveJOSEType "Alg" [
  "RSA1_5"                -- RSAES-PKCS1-V1_5                       Required
  , "RSA-OAEP"            -- RSAES using OAEP                       Optional
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
  , "PBES2-HS384+A128KW"  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  , "PBES2-HS512+A128KW"  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  ])
