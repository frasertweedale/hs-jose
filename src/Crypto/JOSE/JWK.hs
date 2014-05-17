-- Copyright (C) 2013  Fraser Tweedale
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

module Crypto.JOSE.JWK
  (
    JWK(..)
  , materialJWK
  , genRSA

  , JWKSet(..)
  ) where

import Control.Applicative
import Control.Arrow
import Data.Maybe (catMaybes)

import Data.Aeson

import Crypto.JOSE.Classes
import qualified Crypto.JOSE.JWA.JWE.Alg as JWA.JWE
import qualified Crypto.JOSE.JWA.JWK as JWA.JWK
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.TH
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
-- JWK §3.3.  "key_ops" (Key Operations) Parameter
--

$(Crypto.JOSE.TH.deriveJOSEType "KeyOp"
  [ "sign", "verify", "encrypt", "decrypt"
  , "wrapKey", "unwrapKey", "deriveKey", "deriveBits"
  ])


--
-- JWK §3.2.  "use" (Public Key Use) Parameter
--

$(Crypto.JOSE.TH.deriveJOSEType "KeyUse" ["sig", "enc"])


--
-- JWK §3.  JSON Web Key (JWK) Format
--

data JWK =
  JWK {
    jwkMaterial :: JWA.JWK.KeyMaterial,
    jwkUse :: Maybe KeyUse,
    jwkKeyOps :: Maybe [KeyOp],
    jwkAlg :: Maybe Alg,
    jwkKid :: Maybe String,
    jwkX5u :: Maybe Types.URI,
    jwkX5t :: Maybe Types.Base64SHA1,
    jwkX5c :: Maybe [Types.Base64X509]
    }
  deriving (Eq, Show)

instance FromJSON JWK where
  parseJSON = withObject "JWK" (\o -> JWK <$>
    parseJSON (Object o) <*>
    o .:? "use" <*>
    o .:? "key_ops" <*>
    o .:? "alg" <*>
    o .:? "kid" <*>
    o .:? "x5u" <*>
    o .:? "x5t" <*>
    o .:? "x5c")

instance ToJSON JWK where
  toJSON (JWK {..}) = object $ catMaybes
    [ fmap ("alg" .=) jwkAlg
    , fmap ("use" .=) jwkUse
    , fmap ("key_ops" .=) jwkKeyOps
    , fmap ("kid" .=) jwkKid
    , fmap ("x5u" .=) jwkX5u
    , fmap ("x5t" .=) jwkX5t
    , fmap ("x5c" .=) jwkX5c
    ]
    ++ Types.objectPairs (toJSON jwkMaterial)

instance Key JWK where
  sign h k = sign h $ jwkMaterial k
  verify h k = verify h $ jwkMaterial k

materialJWK :: JWA.JWK.KeyMaterial -> JWK
materialJWK m = JWK m n n n n n n n where n = Nothing

genRSA :: Int -> IO (JWK, JWK)
genRSA = fmap (materialJWK *** materialJWK) . JWA.JWK.genRSA


--
-- JWK §4.  JSON Web Key Set (JWK Set) Format
--

data JWKSet = JWKSet [JWK]

instance FromJSON JWKSet where
  parseJSON = withObject "JWKSet" (\o -> JWKSet <$> o .: "keys")
