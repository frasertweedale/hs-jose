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

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.JOSE.JWA.JWE.Alg where

import Control.Applicative
import Data.Tuple
import GHC.Generics (Generic)

import Data.Aeson
import Data.Hashable
import qualified Data.HashMap.Strict as M


--
-- JWA §4.1.  "alg" (Algorithm) Header Parameter Values for JWE
--
-- This section is shuffled off into its own module to avoid
-- circular import via Crypto.JOSE.JWK, which needs Alg.
--

data Alg =
  RSA1_5                -- RSAES-PKCS1-V1_5                       Required
  | RSA_OAEP            -- RSAES using OAEP                       Optional
  | A128KW              -- AES Key Wrap                           Recommended
  | A192KW              -- AES Key Wrap                           Optional
  | A256KW              -- AES Key Wrap                           Recommended
  | Dir                 -- direct use of symmetric key            Recommended
  | ECDH_ES             -- ECDH Ephemeral Static                  Recommended+
  | ECDH_ES_A128KW      --                                        Recommended
  | ECDH_ES_A192KW      --                                        Optional
  | ECDH_ES_A256KW      --                                        Recommended
  | A128GCMKW           -- AES in Galois/Counter Mode             Optional
  | A192GCMKW           -- AES in Galois/Counter Mode             Optional
  | A256GCMKW           -- AES in Galois/Counter Mode             Optional
  | PBES2_HS256_A128KW  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  | PBES2_HS384_A128KW  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  | PBES2_HS512_A128KW  -- PBES2 with HMAC SHA and AES Key Wrap   Optional
  deriving (Eq, Generic, Show)

instance Hashable Alg

-- TODO: is there some bijection data type that does this?
algList = [
  ("RSA1_5",              RSA1_5),
  ("RSA-OAEP",            RSA_OAEP),
  ("A128KW",              A128KW),
  ("A192KW",              A192KW),
  ("A256KW",              A256KW),
  ("dir",                 Dir),
  ("ECDH-ES",             ECDH_ES),
  ("ECDH-ES+A128KW",      ECDH_ES_A128KW),
  ("ECDH-ES+A192KW",      ECDH_ES_A192KW),
  ("ECDH-ES+A256KW",      ECDH_ES_A256KW),
  ("A128GCMKW",           A128GCMKW),
  ("A192GCMKW",           A192GCMKW),
  ("A256GCMKW",           A256GCMKW),
  ("PBES2-HS256+A128KW",  PBES2_HS256_A128KW),
  ("PBES2-HS384+A128KW",  PBES2_HS384_A128KW),
  ("PBES2-HS512+A128KW",  PBES2_HS512_A128KW)
  ]
algMap = M.fromList algList
algMap' = M.fromList $ map swap algList

instance FromJSON Alg where
  parseJSON (String s) = case M.lookup s algMap of
    Just v -> pure v
    Nothing -> fail "undefined JWE alg"

instance ToJSON Alg where
  toJSON alg = String $ M.lookupDefault "?" alg algMap'
