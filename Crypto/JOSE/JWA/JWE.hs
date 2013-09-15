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
import Data.Tuple
import GHC.Generics (Generic)

import Data.Aeson
import Data.Hashable
import qualified Data.HashMap.Strict as M


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

encMap = M.fromList [
  ("A128CBC-HS256", A128CBC_HS256),
  ("A192CBC-HS384", A192CBC_HS384),
  ("A256CBC-HS512", A256CBC_HS512),
  ("A128GCM", A128GCM),
  ("A192GCM", A192GCM),
  ("A256GCM", A256GCM)
  ]

instance FromJSON Enc where
  parseJSON (String s) = case M.lookup s encMap of
    Just v -> pure v
    Nothing -> fail "unrecognised JWE enc value"
