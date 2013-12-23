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

module Crypto.JOSE.Legacy where

import Control.Applicative
import Control.Arrow

import Data.Aeson

import Crypto.JOSE.Classes
import Crypto.JOSE.JWA.JWK
import qualified Crypto.JOSE.Types as Types
import Crypto.JOSE.TH


$(Crypto.JOSE.TH.deriveJOSEType "RS" ["RS"])


newtype RSAKeyParameters' = RSAKeyParameters' RSAKeyParameters
  deriving (Eq, Show)

instance FromJSON RSAKeyParameters' where
  parseJSON = withObject "RSA" (\o ->
    RSAKeyParameters' <$> (RSAPrivateKeyParameters
      <$> o .: "modulus"
      <*> o .: "exponent"
      <*> o .: "secretExponent"
      <*> pure Nothing)
    <|> RSAKeyParameters' <$> (RSAPublicKeyParameters
      <$> o .: "modulus"
      <*> o .: "exponent")
    )

instance ToJSON RSAKeyParameters' where
  toJSON (RSAKeyParameters' (RSAPrivateKeyParameters n e d _)) = object
    ["modulus" .= n ,"exponent" .= e ,"secretExponent" .= d]
  toJSON (RSAKeyParameters' (RSAPublicKeyParameters n e))
    = object ["modulus" .= n, "exponent" .= e]

instance Key RSAKeyParameters' where
  sign h (RSAKeyParameters' k) = sign h k
  verify h (RSAKeyParameters' k) = verify h k


data KeyMaterial' = RSAKeyMaterial' RS RSAKeyParameters' deriving (Eq, Show)

instance FromJSON KeyMaterial' where
  parseJSON = withObject "KeyMaterial'" (\o ->
    RSAKeyMaterial' <$> o .: "algorithm" <*> parseJSON (Object o))

instance ToJSON KeyMaterial' where
  toJSON (RSAKeyMaterial' a k)
    = object $ ("algorithm" .= a) : Types.objectPairs (toJSON k)

instance Key KeyMaterial' where
  sign h (RSAKeyMaterial' _ k) = sign h k
  verify h (RSAKeyMaterial' _ k) = verify h k


newtype JWK' = JWK' KeyMaterial' deriving (Eq, Show)

instance FromJSON JWK' where
  parseJSON = withObject "JWK'" $ \o -> JWK' <$> parseJSON (Object o)

instance ToJSON JWK' where
  toJSON (JWK' k) = object $
    "version" .= ("2012.08.15" :: String) : Types.objectPairs (toJSON k)

instance Key JWK' where
  sign h (JWK' k) = sign h k
  verify h (JWK' k) = verify h k


genRSA' :: Int -> IO (JWK', JWK')
genRSA' =
  let f = JWK' . RSAKeyMaterial' RS . RSAKeyParameters'
  in fmap (f *** f) . genRSAParams
