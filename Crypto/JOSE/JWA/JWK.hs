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

module Crypto.JOSE.JWA.JWK where

import Control.Applicative
import Data.Maybe

import Data.Aeson

import qualified Crypto.JOSE.TH
import qualified Crypto.JOSE.Types as Types


--
-- JWA §5.1.  "kty" (Key Type) Parameter Values
--

$(Crypto.JOSE.TH.deriveJOSEType "EC" ["EC"])    -- Recommended+
$(Crypto.JOSE.TH.deriveJOSEType "RSA" ["RSA"])  -- Required
$(Crypto.JOSE.TH.deriveJOSEType "Oct" ["oct"])  -- Required


--
-- JWA §5.2.1.1.  "crv" (Curve) Parameter
--

$(Crypto.JOSE.TH.deriveJOSEType "Crv" ["P-256", "P-384", "P-521"])


--
-- JWA §5.3.2.7.  "oth" (Other Primes Info) Parameter
--

data RSAPrivateKeyOthElem = RSAPrivateKeyOthElem {
  rOth :: Types.Base64Integer,
  dOth :: Types.Base64Integer,
  tOth :: Types.Base64Integer
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOthElem where
  parseJSON = withObject "oth" (\o -> RSAPrivateKeyOthElem <$>
    o .: "r" <*>
    o .: "d" <*>
    o .: "t")

instance ToJSON RSAPrivateKeyOthElem where
  toJSON (RSAPrivateKeyOthElem r d t) = object ["r" .= r, "d" .= d, "t" .= t]


--
-- JWA §5.3.2.  JWK Parameters for RSA Private Keys
--

data RSAPrivateKeyOptionalParameters = RSAPrivateKeyOptionalParameters {
  rsaP :: Maybe Types.Base64Integer,
  rsaQ :: Maybe Types.Base64Integer,
  rsaDp :: Maybe Types.Base64Integer,
  rsaDq :: Maybe Types.Base64Integer,
  rsaQi :: Maybe Types.Base64Integer,
  rsaOth :: Maybe [RSAPrivateKeyOthElem] -- TODO oth must not be empty array
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOptionalParameters where
  parseJSON = withObject "RSA" (\o -> RSAPrivateKeyOptionalParameters <$>
    o .: "p" <*>
    o .: "q" <*>
    o .: "dp" <*>
    o .: "dq" <*>
    o .: "qi" <*>
    o .:? "oth")

instance ToJSON RSAPrivateKeyOptionalParameters where
  toJSON (RSAPrivateKeyOptionalParameters p q dp dq qi oth) = object $ [
    "p" .= p
    , "q" .= q
    , "dp" .= dp
    , "dq" .= dq
    , "dq" .= qi
    ] ++ map ("oth" .=) (maybeToList oth)


--
-- JWA §5.  Cryptographic Algorithms for JWK
--

data ECKeyParameters =
  ECPrivateKeyParameters {
    ecD :: Types.SizedBase64Integer
    }
  | ECPublicKeyParameters {
    ecCrv :: Crv,
    ecX :: Types.SizedBase64Integer,
    ecY :: Types.SizedBase64Integer
    }
  deriving (Eq, Show)

instance FromJSON ECKeyParameters where
  parseJSON = withObject "EC" (\o ->
    ECPrivateKeyParameters    <$> o .: "d"
    <|> ECPublicKeyParameters <$> o .: "crv" <*> o .: "x" <*> o .: "y")

instance ToJSON ECKeyParameters where
  toJSON (ECPrivateKeyParameters d) = object ["d" .= d]
  toJSON (ECPublicKeyParameters crv x y) = object [
    "crv" .= crv
    , "x" .= x
    , "y" .= y
    ]


data RSAKeyParameters =
  RSAPrivateKeyParameters {
    rsaD :: Types.SizedBase64Integer,
    rsaOptionalParameters :: Maybe RSAPrivateKeyOptionalParameters
    }
  | RSAPublicKeyParameters {
    rsaN :: Types.Base64Integer,
    rsaE :: Types.Base64Integer
    }
  deriving (Eq, Show)

instance FromJSON RSAKeyParameters where
  parseJSON = withObject "RSA" (\o ->
    RSAPrivateKeyParameters    <$> o .: "d" <*> parseJSON (Object o)
    <|> RSAPublicKeyParameters <$> o .: "n" <*> o .: "e")

instance ToJSON RSAKeyParameters where
  toJSON (RSAPrivateKeyParameters d params) = object $
    ("d" .= d) : Types.objectPairs (toJSON params)
  toJSON (RSAPublicKeyParameters n e) = object ["n" .= n, "e" .= e]


data KeyMaterial =
  ECKeyMaterial EC ECKeyParameters
  | RSAKeyMaterial RSA RSAKeyParameters
  | OctKeyMaterial Oct Types.Base64Integer
  deriving (Eq, Show)

instance FromJSON KeyMaterial where
  parseJSON = withObject "KeyMaterial" (\o ->
    ECKeyMaterial      <$> o .: "kty" <*> parseJSON (Object o)
    <|> RSAKeyMaterial <$> o .: "kty" <*> parseJSON (Object o)
    <|> OctKeyMaterial <$> o .: "kty" <*> o .: "k")

instance ToJSON KeyMaterial where
  toJSON (ECKeyMaterial k p)  = object $ ("kty" .= k) : Types.objectPairs (toJSON p)
  toJSON (RSAKeyMaterial k p) = object $ ("kty" .= k) : Types.objectPairs (toJSON p)
  toJSON (OctKeyMaterial k i) = object ["kty" .= k, "k" .= i]
