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
import Data.Maybe (catMaybes)

import Data.Aeson
import qualified Network.URI

import qualified Crypto.JOSE.JWA.JWE.Alg as JWA.JWE
import qualified Crypto.JOSE.JWA.JWK as JWA.JWK
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.Types as Types


--
-- JWK §3.3.  "alg" (Algorithm) Parameter
--

data Alg = JWSAlg JWA.JWS.Alg | JWEAlg JWA.JWE.Alg
  deriving (Eq, Show)

instance FromJSON Alg where
  parseJSON v = (JWSAlg <$> parseJSON v) <|> (JWEAlg <$> parseJSON v)

instance ToJSON Alg where
  toJSON (JWSAlg alg) = toJSON alg
  toJSON (JWEAlg alg) = toJSON alg


--
-- JWK §3.  JSON Web Key (JWK) Format
--

data Key =
  Key {
    keyMaterial :: JWA.JWK.KeyMaterial,
    keyUse :: Maybe String,
    keyAlg :: Maybe Alg,
    keyKid :: Maybe String,
    keyX5u :: Maybe Network.URI.URI,
    keyX5t :: Maybe Types.Base64SHA1,
    keyX5c :: Maybe [Types.Base64X509]
    }
  deriving (Eq, Show)

instance FromJSON Key where
  parseJSON = withObject "Key" (\o -> Key <$>
    parseJSON (Object o) <*>
    o .:? "use" <*>
    o .:? "alg" <*>
    o .:? "kid" <*>
    o .:? "x5u" <*>
    o .:? "x5t" <*>
    o .:? "x5c")

instance ToJSON Key where
  toJSON (Key key use alg kid x5u x5t x5c) = object $ catMaybes [
    fmap ("use" .=) use
    , fmap ("alg" .=) alg
    , fmap ("kid" .=) kid
    , fmap ("x5u" .=) x5u
    , fmap ("x5t" .=) x5t
    , fmap ("x5c" .=) x5c
    ]
    ++ Types.objectPairs (toJSON key)


--
-- JWK §4.  JSON Web Key Set (JWK Set) Format
--

data KeySet = KeySet [Key]

instance FromJSON KeySet where
  parseJSON = withObject "KeySet" (\o -> KeySet <$> o .: "keys")
