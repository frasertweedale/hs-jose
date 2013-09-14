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

module Crypto.JOSE.JWA where

import Control.Applicative
import Data.Tuple
import GHC.Generics (Generic)

import Data.Aeson
import Data.Hashable
import qualified Data.HashMap.Strict as M

import qualified Crypto.JOSE.Integer as JI

-- TODO QQ or TH this rubbish

data JWSAlg =
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
  | None   -- "none" No signature or MAC ; REQUIRED
  deriving (Eq, Generic, Show)

instance Hashable JWSAlg

-- TODO: is there some bijection data type that does this?
jwsAlgList = [
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
jwsAlgMap = M.fromList jwsAlgList
jwsAlgMap' = M.fromList $ map swap jwsAlgList
jwsAlgToKey alg = M.lookup alg jwsAlgMap'

instance FromJSON JWSAlg where
  parseJSON (String s) = case M.lookup s jwsAlgMap of
    Just v -> pure v
    Nothing -> fail "undefined JWS alg"

data JWEAlg =
  RSA1_5 -- RSAES-PKCS1-V1_5 [RFC3447]      | REQUIRED
  deriving (Show)

jweAlgMap = M.fromList [
  ("RSA1_5", RSA1_5)
  ]

data Alg = JWSAlg JWSAlg | JWEAlg JWEAlg
  deriving (Show)

instance FromJSON Alg where
  parseJSON (String s) = case M.lookup s jweAlgMap of
    Just v -> pure $ JWEAlg v
    Nothing -> case M.lookup s jwsAlgMap of
      Just v -> pure $ JWSAlg v
      Nothing -> fail "undefined alg"
  parseJSON _ = empty


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
crvToKey crv = M.lookup crv crvMap'

instance FromJSON Crv where
  parseJSON (String s) = case M.lookup s crvMap of
    Just v -> pure v
    Nothing -> fail "undefined EC crv"


data RSAPrivateKeyOthElem = RSAPrivateKeyOthElem {
  r' :: JI.Base64Integer,
  d' :: JI.Base64Integer,
  t' :: JI.Base64Integer
  }
  deriving (Show)

instance FromJSON RSAPrivateKeyOthElem where
  parseJSON (Object o) = RSAPrivateKeyOthElem <$>
    o .: "r" <*>
    o .: "d" <*>
    o .: "t"
  parseJSON _ = empty


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
    n :: JI.SizedBase64Integer,
    e :: JI.Base64Integer
    }
  | RSAPrivateKeyParameters {
    d :: JI.SizedBase64Integer,
    p :: JI.Base64Integer,
    q :: JI.Base64Integer,
    dp :: JI.Base64Integer,
    dq :: JI.Base64Integer,
    qi :: JI.Base64Integer,
    -- TODO oth must not be empty array
    oth :: Maybe [RSAPrivateKeyOthElem]
    }
  deriving (Show)

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
        o .: "p" <*>
        o .: "q" <*>
        o .: "dp" <*>
        o .: "dq" <*>
        o .: "qi" <*>
        o .:? "oth"
      <|> RSAPublicKeyParameters <$>
        o .: "n" <*>
        o .: "e"
    | otherwise = empty
  parseJSON _ = empty
