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

module Crypto.JOSE.JWA.JWE where

import Control.Applicative

import Data.Aeson
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T

import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.Types as Types


--
-- JWA §4.  Cryptographic Algorithms for Encryption
--

--
-- JWA 4.1.  "alg" (Algorithms) Header Parameter Values for JWE

data JWEAlgHeaderParameters =
  -- JWA §4.7.1.  Header Parameters Used for ECDH Key Agreement
  ECDHParameters {
    epk :: JWK.Key,   -- Ephemeral Public Key ; a JWK PUBLIC key
    apu :: Maybe Types.Base64UrlString, -- Agreement PartyUInfo
    apv :: Maybe Types.Base64UrlString  -- Agreement PartyVInfo
    }
  -- JWA §4.8.1.  Header Parameters Used for AES GCM Key Encryption
  | AESGCMParameters {
    iv :: Types.Base64Octets, -- Initialization Vector
    tag :: Types.Base64Octets -- Authentication Tag
    }
  -- JWA §4.9.1.  Header Parameters Used for PBES2 Key Encryption
  | PBES2Parameters {
    p2s :: Types.Base64Octets,  -- PBKDF2 salt value
    p2c :: Int                  -- PBKDF2 iteration count ; POSITIVE integer
    }
  deriving (Show)


--
-- JWA §4.2.  "enc" (Encryption Method) Header Parameters Values for JWE
--

data Enc =
  A128CBC_HS256   -- AES HMAC SHA authenticated encryption  Required
  | A192CBC_HS384 -- AES HMAC SHA authenticated encryption  Optional
  | A256CBC_HS512 -- AES HMAC SHA authenticated encryption  Required
  | A128GCM       -- AES in Galois/Counter Mode             Recommended
  | A192GCM       -- AES in Galois/Counter Mode             Optional
  | A256GCM       -- AES in Galois/Counter Mode             Recommended

encMap :: M.HashMap T.Text Enc
encMap = M.fromList [
  ("A128CBC-HS256", A128CBC_HS256),
  ("A192CBC-HS384", A192CBC_HS384),
  ("A256CBC-HS512", A256CBC_HS512),
  ("A128GCM", A128GCM),
  ("A192GCM", A192GCM),
  ("A256GCM", A256GCM)
  ]

instance FromJSON Enc where
  parseJSON = withText "enc" (\s ->
    maybe (fail "unrecognised JWE enc value") pure $ M.lookup s encMap)
