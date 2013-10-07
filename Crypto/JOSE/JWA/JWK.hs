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
{-# LANGUAGE PatternGuards #-}

module Crypto.JOSE.JWA.JWK where

import Control.Applicative
import Data.Maybe
import Data.Tuple
import GHC.Generics (Generic)

import Data.Aeson
import Data.Hashable
import qualified Data.HashMap.Strict as M

import qualified Crypto.JOSE.Integer as JI


--
-- JWA §5.1.  "kty" (Key Type) Parameter Values
--

data Kty =
  EC    -- Recommended+
  | RSA -- Required
  | Oct -- Required
  deriving (Eq, Show)

instance FromJSON Kty where
  parseJSON (String "EC") = pure EC
  parseJSON (String "RSA") = pure RSA
  parseJSON (String "oct") = pure Oct
  parseJSON _ = fail "undefined kty"

instance ToJSON Kty where
  toJSON EC = String "EC"
  toJSON RSA = String "RSA"
  toJSON Oct = String "oct"


--
-- JWA §5.2.1.1.  "crv" (Curve) Parameter
--

data Crv = P256 | P384 | P521
  deriving (Eq, Show)

instance Hashable Crv

crvList = [
  ("P-256", P256),
  ("P-384", P384),
  ("P-521", P521)
  ]
crvMap = M.fromList crvList
crvMap' = M.fromList $ map swap crvList

instance FromJSON Crv where
  parseJSON (String s) = case M.lookup s crvMap of
    Just v -> pure v
    Nothing -> fail "undefined EC crv"

instance ToJSON Crv where
  toJSON crv = String $ M.lookupDefault "?" crv crvMap'


--
-- JWA §5.3.2.7.  "oth" (Other Primes Info) Parameter
--

data RSAPrivateKeyOthElem = RSAPrivateKeyOthElem {
  r' :: JI.Base64Integer,
  d' :: JI.Base64Integer,
  t' :: JI.Base64Integer
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOthElem where
  parseJSON (Object o) = RSAPrivateKeyOthElem <$>
    o .: "r" <*>
    o .: "d" <*>
    o .: "t"

instance ToJSON RSAPrivateKeyOthElem where
  toJSON (RSAPrivateKeyOthElem r d t) = object ["r" .= r, "d" .= d, "t" .= t]


--
-- JWA §5.3.2.  JWK Parameters for RSA Private Keys
--

data RSAPrivateKeyOptionalParameters = RSAPrivateKeyOptionalParameters {
  p :: Maybe JI.Base64Integer,
  q :: Maybe JI.Base64Integer,
  dp :: Maybe JI.Base64Integer,
  dq :: Maybe JI.Base64Integer,
  qi :: Maybe JI.Base64Integer,
  oth :: Maybe [RSAPrivateKeyOthElem] -- TODO oth must not be empty array
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOptionalParameters where
  parseJSON (Object o) = RSAPrivateKeyOptionalParameters <$>
    o .: "p" <*>
    o .: "q" <*>
    o .: "dp" <*>
    o .: "dq" <*>
    o .: "qi" <*>
    o .:? "oth"

instance ToJSON RSAPrivateKeyOptionalParameters where
  toJSON (RSAPrivateKeyOptionalParameters p q dp dq qi oth) = object $ [
    "p" .= p
    , "q" .= q
    , "dp" .= dp
    , "dq" .= dq
    , "dq" .= qi
    ] ++ (map ("oth" .=) $ maybeToList oth)


--
-- JWA §5.  Cryptographic Algorithms for JWK
--

data KeyParameters =
  ECPublicKeyParameters {
    crv :: Crv,
    x :: JI.SizedBase64Integer,
    y :: JI.SizedBase64Integer
    }
  | ECPrivateKeyParameters {
    d :: JI.SizedBase64Integer
    }
  | RSAPublicKeyParameters {
    n :: JI.Base64Integer,
    e :: JI.Base64Integer
    }
  | RSAPrivateKeyParameters {
    d :: JI.SizedBase64Integer,
    optionalParameters :: Maybe RSAPrivateKeyOptionalParameters
    }
  | SymmetricKeyParameters {
    k :: JI.Base64Integer
    }
  deriving (Eq, Show)

instance FromJSON KeyParameters where
  parseJSON (Object o)
    -- prefer private key; a private key could contain public key
    | Just (String "EC") <- M.lookup "kty" o
    = ECPrivateKeyParameters <$>
        o .: "d"
      <|> ECPublicKeyParameters <$>
        o .: "crv" <*>
        o .: "x" <*>
        o .: "y"
    | Just (String "RSA") <- M.lookup "kty" o
    = RSAPrivateKeyParameters <$>
        o .: "d" <*>
        parseJSON (Object o)
      <|> RSAPublicKeyParameters <$>
        o .: "n" <*>
        o .: "e"
    | Just (String "oct") <- M.lookup "key" o
    = SymmetricKeyParameters <$> o .: "k"
    | otherwise = empty
  parseJSON _ = empty

instance ToJSON KeyParameters where
  toJSON (ECPrivateKeyParameters d) = object ["d" .= d]
  toJSON (ECPublicKeyParameters crv x y) = object [
    "crv" .= crv
    , "x" .= x
    , "y" .= y
    ]
  toJSON (RSAPrivateKeyParameters d params) = object (
    ["d" .= d]
    ++ (objectPairs $ toJSON params)
    )
    where objectPairs (Object o) = M.toList o
  toJSON (RSAPublicKeyParameters n e) = object ["n" .= n, "e" .= e]
  toJSON (SymmetricKeyParameters k) = object ["k" .= k]
