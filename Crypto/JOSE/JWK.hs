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

module Crypto.JOSE.JWK where

import Control.Applicative

import Data.Aeson

import qualified Crypto.JOSE.JWA as JWA
import qualified Crypto.JOSE.JWA.JWK as JWA.JWK


data Key =
  Key {
    kty :: JWA.JWK.Kty,
    use :: Maybe String,
    alg :: Maybe JWA.Alg,
    kid :: Maybe String,
    x5u :: Maybe String,    -- X.509 URL
    x5t :: Maybe String,    -- base64url SHA-1 digest of DER of X.509 cert
    x5c :: Maybe [String],  -- X.509 certificate chain
    params :: JWA.JWK.KeyParameters
    }
  | NullKey  -- convenience constructor for use with "none" alg
  deriving (Show)

instance FromJSON Key where
  parseJSON (Object o) = Key <$>
    o .: "kty" <*>
    o .:? "use" <*>
    o .:? "alg" <*>
    o .:? "kid" <*>
    o .:? "x5u" <*>
    o .:? "x5t" <*>
    o .:? "x5c" <*>
    parseJSON (Object o)
  parseJSON _ = empty


data KeySet = KeySet [Key]

instance FromJSON KeySet where
  parseJSON (Object o) = KeySet <$>
    o .: "keys"
  parseJSON _ = empty
