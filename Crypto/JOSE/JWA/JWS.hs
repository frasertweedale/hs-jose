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

module Crypto.JOSE.JWA.JWS where

import Control.Applicative
import Data.Tuple
import GHC.Generics (Generic)

import Data.Aeson
import Data.Hashable
import qualified Data.HashMap.Strict as M


--
-- JWA §3.1.  "alg" (Algorithm) Header Parameters for JWS
--

data Alg =
  HS256    -- HMAC SHA ; REQUIRED
  | HS384  -- HMAC SHA ; OPTIONAL
  | HS512  -- HMAC SHA ; OPTIONAL
  | RS256  -- RSASSA-PKCS-v1_5 SHA ; RECOMMENDED
  | RS384  -- RSASSA-PKCS-v1_5 SHA ; OPTIONAL
  | RS512  -- RSASSA-PKCS-v1_5 SHA ; OPTIONAL
  | ES256  -- ECDSA P curve and SHA ; RECOMMENDED+
  | ES384  -- ECDSA P curve and SHA ; OPTIONAL
  | ES512  -- ECDSA P curve and SHA ; OPTIONAL
  | PS256  -- RSASSA-PSS SHA ; OPTIONAL
  | PS384  -- RSASSA-PSS SHA ; OPTIONAL
  | PS512  -- RSSSSA-PSS SHA ; OPTIONAL
  | None   -- "none" No signature or MAC ; Optional
  deriving (Eq, Generic, Show)

instance Hashable Alg

-- TODO: is there some bijection data type that does this?
algList = [
  ("HS256", HS256),
  ("HS384", HS384),
  ("HS512", HS512),
  ("RS256", RS256),
  ("RS384", RS384),
  ("RS512", RS512),
  ("ES256", ES256),
  ("ES384", ES384),
  ("ES512", ES512),
  ("PS256", ES256),
  ("PS384", ES384),
  ("PS512", ES512),
  ("none", None)
  ]
algMap = M.fromList algList
algMap' = M.fromList $ map swap algList

instance FromJSON Alg where
  parseJSON (String s) = case M.lookup s algMap of
    Just v -> pure v
    Nothing -> fail "undefined JWS alg"

instance ToJSON Alg where
  toJSON alg = String $ M.lookupDefault "?" alg algMap'
