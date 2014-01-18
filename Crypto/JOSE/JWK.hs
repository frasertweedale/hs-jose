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
-- JWK §3.3.  "use_detail" (Key Use Details) Parameter
--

$(Crypto.JOSE.TH.deriveJOSEType "KeyUseDetailSig" ["sign", "verify"])
$(Crypto.JOSE.TH.deriveJOSEType "KeyUseDetailEnc"
  ["encrypt", "decrypt", "wrap", "unwrap", "deriveKey", "deriveBits"])

data KeyUseDetail
  = KeyUseDetailSig KeyUseDetailSig
  | KeyUseDetailEnc KeyUseDetailEnc
  deriving (Eq, Show)

instance FromJSON KeyUseDetail where
  parseJSON v
      = (KeyUseDetailSig <$> parseJSON v)
    <|> (KeyUseDetailEnc <$> parseJSON v)

instance ToJSON KeyUseDetail where
  toJSON (KeyUseDetailSig a) = toJSON a
  toJSON (KeyUseDetailEnc a) = toJSON a


--
-- JWK §3.2.  "use" (Key Use) Parameter
--

$(Crypto.JOSE.TH.deriveJOSEType "KeyUseSig" ["sig"])
$(Crypto.JOSE.TH.deriveJOSEType "KeyUseEnc" ["enc"])

newtype KeyUseOther = Some String deriving (Eq, Show)

instance FromJSON KeyUseOther where
  parseJSON = withText "other Key Use" (\s -> if s /= "sig" && s /= "enc"
    then parseJSON (String s)
    else fail "mixed use_detail must not be used with sig or enc")

instance ToJSON KeyUseOther where
  toJSON (Some s) = toJSON s


data KeyUse
  = KeyUseSig KeyUseSig (Maybe [KeyUseDetailSig])
  | KeyUseEnc KeyUseEnc (Maybe [KeyUseDetailEnc])
  | KeyUseOther (Maybe KeyUseOther) (Maybe [KeyUseDetail])
  deriving (Eq, Show)

instance FromJSON KeyUse where
  parseJSON = withObject "Key Use" (\o ->
    KeyUseSig <$> o .: "use" <*> o .:? "use_details"
    <|> KeyUseEnc <$> o .: "use" <*> o .:? "use_details"
    <|> KeyUseOther <$> o .:? "use" <*> o .:? "use_details")

instance ToJSON KeyUse where
  toJSON (KeyUseSig use det) = object $
    catMaybes [Just ("use" .= use), fmap ("use_detail" .=) det]
  toJSON (KeyUseEnc use det) = object $
    catMaybes [Just ("use" .= use), fmap ("use_detail" .=) det]
  toJSON (KeyUseOther use det) = object $
    catMaybes [fmap ("use" .=) use, fmap ("use_detail" .=) det]


--
-- JWK §3.  JSON Web Key (JWK) Format
--

data JWK =
  JWK {
    jwkMaterial :: JWA.JWK.KeyMaterial,
    jwkUse :: KeyUse,
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
    parseJSON (Object o) <*>
    o .:? "alg" <*>
    o .:? "kid" <*>
    o .:? "x5u" <*>
    o .:? "x5t" <*>
    o .:? "x5c")

instance ToJSON JWK where
  toJSON (JWK key use alg kid x5u x5t x5c) = object $ catMaybes
    [ fmap ("alg" .=) alg
    , fmap ("kid" .=) kid
    , fmap ("x5u" .=) x5u
    , fmap ("x5t" .=) x5t
    , fmap ("x5c" .=) x5c
    ]
    ++ Types.objectPairs (toJSON key)
    ++ Types.objectPairs (toJSON use)

instance Key JWK where
  sign h k = sign h $ jwkMaterial k
  verify h k = verify h $ jwkMaterial k

materialJWK :: JWA.JWK.KeyMaterial -> JWK
materialJWK m = JWK m (KeyUseOther n n) n n n n n where n = Nothing

genRSA :: Int -> IO (JWK, JWK)
genRSA = fmap (materialJWK *** materialJWK) . JWA.JWK.genRSA


--
-- JWK §4.  JSON Web Key Set (JWK Set) Format
--

data JWKSet = JWKSet [JWK]

instance FromJSON JWKSet where
  parseJSON = withObject "JWKSet" (\o -> JWKSet <$> o .: "keys")
