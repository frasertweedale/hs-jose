-- Copyright (C) 2013, 2014, 2015  Fraser Tweedale
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

{-|

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
structure that represents a cryptographic key.  This module also
defines a JSON Web Key Set (JWK Set) JSON data structure for
representing a set of JWKs.

-}
module Crypto.JOSE.JWK
  (
    JWK(JWK)
  , jwkMaterial
  , jwkUse
  , jwkKeyOps
  , jwkAlg
  , jwkKid
  , jwkX5u
  , jwkX5c
  , jwkX5t
  , jwkX5tS256

  , JWKSet(..)

  , module Crypto.JOSE.JWA.JWK
  ) where

import Control.Applicative
import Data.Maybe (catMaybes)

import Control.Lens hiding ((.=))
import Data.Aeson
import Data.List.NonEmpty

import Test.QuickCheck

import Crypto.JOSE.Classes
import qualified Crypto.JOSE.JWA.JWE.Alg as JWA.JWE
import Crypto.JOSE.JWA.JWK
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.TH
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types


-- | JWK §3.3.  "alg" (Algorithm) Parameter
--
data Alg = JWSAlg JWA.JWS.Alg | JWEAlg JWA.JWE.Alg
  deriving (Eq, Show)

instance FromJSON Alg where
  parseJSON v = (JWSAlg <$> parseJSON v) <|> (JWEAlg <$> parseJSON v)

instance ToJSON Alg where
  toJSON (JWSAlg alg) = toJSON alg
  toJSON (JWEAlg alg) = toJSON alg


-- | JWK §3.3.  "key_ops" (Key Operations) Parameter
--
$(Crypto.JOSE.TH.deriveJOSEType "KeyOp"
  [ "sign", "verify", "encrypt", "decrypt"
  , "wrapKey", "unwrapKey", "deriveKey", "deriveBits"
  ])


-- | JWK §3.2.  "use" (Public Key Use) Parameter
--
$(Crypto.JOSE.TH.deriveJOSEType "KeyUse" ["sig", "enc"])


-- | JWK §3.  JSON Web Key (JWK) Format
--
data JWK = JWK
  {
    _jwkMaterial :: Crypto.JOSE.JWA.JWK.KeyMaterial
  , _jwkUse :: Maybe KeyUse
  , _jwkKeyOps :: Maybe [KeyOp]
  , _jwkAlg :: Maybe Alg
  , _jwkKid :: Maybe String
  , _jwkX5u :: Maybe Types.URI
  , _jwkX5c :: Maybe (NonEmpty Types.Base64X509)
  , _jwkX5t :: Maybe Types.Base64SHA1
  , _jwkX5tS256 :: Maybe Types.Base64SHA256
  }
  deriving (Eq, Show)
makeLenses ''JWK

instance FromJSON JWK where
  parseJSON = withObject "JWK" $ \o -> JWK
    <$> parseJSON (Object o)
    <*> o .:? "use"
    <*> o .:? "key_ops"
    <*> o .:? "alg"
    <*> o .:? "kid"
    <*> o .:? "x5u"
    <*> o .:? "x5c"
    <*> o .:? "x5t"
    <*> o .:? "x5t#S256"

instance ToJSON JWK where
  toJSON (JWK {..}) = object $ catMaybes
    [ fmap ("alg" .=) _jwkAlg
    , fmap ("use" .=) _jwkUse
    , fmap ("key_ops" .=) _jwkKeyOps
    , fmap ("kid" .=) _jwkKid
    , fmap ("x5u" .=) _jwkX5u
    , fmap ("x5c" .=) _jwkX5c
    , fmap ("x5t" .=) _jwkX5t
    , fmap ("x5t#S256" .=) _jwkX5tS256
    ]
    ++ Types.objectPairs (toJSON _jwkMaterial)

instance Key JWK where
  type KeyGenParam JWK = Crypto.JOSE.JWA.JWK.KeyMaterialGenParam
  type KeyContent JWK = Crypto.JOSE.JWA.JWK.KeyMaterial
  gen p = fromKeyContent <$> gen p
  fromKeyContent k = JWK k z z z z z z z z where z = Nothing
  public = jwkMaterial public
  sign h k = sign h $ k ^. jwkMaterial
  verify h k = verify h $ k ^. jwkMaterial

instance Arbitrary JWK where
  arbitrary = JWK
    <$> arbitrary
    <*> pure Nothing
    <*> pure Nothing
    <*> pure Nothing
    <*> arbitrary
    <*> pure Nothing
    <*> pure Nothing
    <*> arbitrary
    <*> arbitrary


-- | JWK §4.  JSON Web Key Set (JWK Set) Format
--
newtype JWKSet = JWKSet [JWK] deriving (Eq, Show)

instance FromJSON JWKSet where
  parseJSON = withObject "JWKSet" (\o -> JWKSet <$> o .: "keys")
