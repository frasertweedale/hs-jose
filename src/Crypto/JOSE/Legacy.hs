-- Copyright (C) 2013, 2014  Fraser Tweedale
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
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

{-|

Types to deal with the legacy JSON Web Key formats used with
Mozilla Persona.

-}
module Crypto.JOSE.Legacy
  (
    JWK'(..)
  , toJWK
  , RSKeyParameters()
  , rsaKeyParameters
  ) where

import Control.Applicative
import Data.Bifunctor

import Control.Lens (makeLenses)
import Data.Aeson
import Data.Aeson.Types

import Crypto.JOSE.Classes
import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types.Internal as Types
import Crypto.JOSE.TH


$(Crypto.JOSE.TH.deriveJOSEType "RS" ["RS"])


newtype RSKeyParameters = RSKeyParameters { _rsaKeyParameters :: RSAKeyParameters }
  deriving (Eq, Show)
makeLenses ''RSKeyParameters

instance FromJSON RSKeyParameters where
  parseJSON = withObject "RS" $ \o -> fmap RSKeyParameters $ RSAKeyParameters
    <$> ((o .: "algorithm" :: Parser RS) *> pure RSA)
    <*> o .: "modulus"
    <*> o .: "exponent"
    <*> (fmap (`RSAPrivateKeyParameters` Nothing) <$> (o .:? "secretExponent"))

instance ToJSON RSKeyParameters where
  toJSON (RSKeyParameters (RSAKeyParameters _ n e priv))
    = object $ ["algorithm" .= RS, "modulus" .= n ,"exponent" .= e]
      ++ maybe [] (\p -> ["secretExponent" .= rsaD p]) priv

instance Key RSKeyParameters where
  type KeyGenParam RSKeyParameters = Int
  type KeyContent RSKeyParameters = RSAKeyParameters
  gen p = first fromKeyContent . gen p
  fromKeyContent = RSKeyParameters
  public = rsaKeyParameters public
  sign h (RSKeyParameters k) = sign h k
  verify h (RSKeyParameters k) = verify h k


-- | Legacy JSON Web Key data type.
--
newtype JWK' = JWK' { _rsKeyParameters :: RSKeyParameters }
  deriving (Eq, Show)
makeLenses ''JWK'

instance FromJSON JWK' where
  parseJSON = withObject "JWK'" $ \o -> JWK' <$> parseJSON (Object o)

instance ToJSON JWK' where
  toJSON (JWK' k) = object $
    "version" .= ("2012.08.15" :: String) : Types.objectPairs (toJSON k)

instance Key JWK' where
  type KeyGenParam JWK' = Int
  type KeyContent JWK' = RSKeyParameters
  gen p g = first JWK' $ gen p g
  fromKeyContent = JWK'
  public = rsKeyParameters public
  sign h (JWK' k) = sign h k
  verify h (JWK' k) = verify h k

toJWK :: JWK' -> JWK
toJWK (JWK' (RSKeyParameters k)) = fromKeyContent $ RSAKeyMaterial k
