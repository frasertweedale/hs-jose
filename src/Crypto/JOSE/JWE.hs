-- Copyright (C) 2015  Fraser Tweedale
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

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.JOSE.JWE
  (
    JWEHeader(..)

  , JWE(..)
  ) where

import Prelude hiding (mapM)
import Control.Applicative
import Data.Bifunctor (first)
import Data.Maybe (catMaybes)
import Data.Traversable (mapM)

import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.List.NonEmpty (NonEmpty(..), toList)

import Crypto.JOSE.Error
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types
import Crypto.JOSE.Types.Armour


critInvalidNames :: [T.Text]
critInvalidNames =
  [ "alg" , "enc" , "zip" , "jku" , "jwk" , "kid"
  , "x5u" , "x5c" , "x5t" , "x5t#S256" , "typ" , "cty" , "crit" ]

newtype CritParameters = CritParameters (NonEmpty (T.Text, Value))
  deriving (Eq, Show)

critObjectParser :: Object -> T.Text -> Parser (T.Text, Value)
critObjectParser o s
  | s `elem` critInvalidNames = fail "crit key is reserved"
  | otherwise                 = (\v -> (s, v)) <$> o .: s

parseCrit :: Object -> NonEmpty T.Text -> Parser CritParameters
parseCrit o = fmap CritParameters . mapM (critObjectParser o)
  -- TODO fail on duplicate strings

instance FromJSON CritParameters where
  parseJSON = withObject "crit" $ \o -> o .: "crit" >>= parseCrit o

instance ToJSON CritParameters where
  toJSON (CritParameters m) = object $ ("crit", toJSON $ fmap fst m) : toList m


data JWEHeader = JWEHeader
  { _jweAlg :: Maybe AlgWithParams
  , _jweEnc :: Maybe Enc
  , _jweZip :: Maybe String  -- protected header only  "DEF" (DEFLATE) defined
  , _jweJku :: Maybe Types.URI
  , _jweJwk :: Maybe JWK
  , _jweKid :: Maybe String
  , _jweX5u :: Maybe Types.URI
  , _jweX5c :: Maybe (NonEmpty Types.Base64X509)
  , _jweX5t :: Maybe Types.Base64SHA1
  , _jweX5tS256 :: Maybe Types.Base64SHA256
  , _jweTyp :: Maybe String  -- ^ Content Type (of object)
  , _jweCty :: Maybe String  -- ^ Content Type (of payload)
  , _jweCrit :: Maybe CritParameters
  }
  deriving (Eq, Show)

instance FromJSON JWEHeader where
  parseJSON = withObject "JWE" $ \o -> JWEHeader
    <$> parseJSON (Object o)
    <*> o .: "enc"
    <*> o .:? "zip"
    <*> o .:? "jku"
    <*> o .:? "jwk"
    <*> o .:? "kid"
    <*> o .:? "x5u"
    <*> o .:? "x5c"
    <*> o .:? "x5t"
    <*> o .:? "x5t#S256"
    <*> o .:? "typ"
    <*> o .:? "cty"
    <*> (o .:? "crit" >>= mapM (parseCrit o))  -- TODO

instance ToJSON JWEHeader where
  toJSON (JWEHeader alg enc _zip jku jwk kid x5u x5c x5t x5tS256 typ cty crit) =
    object $ catMaybes
      [ fmap ("enc" .=) enc
      , fmap ("zip" .=) _zip
      , fmap ("jku" .=) jku
      , fmap ("jwk" .=) jwk
      , fmap ("kid" .=) kid
      , fmap ("x5u" .=) x5u
      , fmap ("x5c" .=) x5c
      , fmap ("x5t" .=) x5t
      , fmap ("x5t#S256" .=) x5tS256
      , fmap ("typ" .=) typ
      , fmap ("cty" .=) cty
      ]
      ++ Types.objectPairs (toJSON crit)
      ++ maybe [] (Types.objectPairs . toJSON) alg

instance FromArmour T.Text Error JWEHeader where
  parseArmour s =
        first (compactErr "header")
          (B64UL.decode (L.fromStrict $ Types.pad $ T.encodeUtf8 s))
        >>= first JSONDecodeError . eitherDecode
    where
    compactErr s' = CompactDecodeError . ((s' ++ " decode failed: ") ++)

instance ToArmour T.Text JWEHeader where
  toArmour = T.decodeUtf8 . Types.unpad . B64U.encode . L.toStrict . encode


data JWERecipient = JWERecipient
  { _jweHeader :: Maybe JWEHeader -- ^ JWE Per-Recipient Unprotected Header
  , _jweEncryptedKey :: Maybe Types.Base64Octets  -- ^ JWE Encrypted Key
  }

instance FromJSON JWERecipient where
  parseJSON = withObject "JWE Recipient" $ \o -> JWERecipient
    <$> o .:? "header"
    <*> o .:? "encrypted_key"

data JWE = JWE
  { _jweProtected :: Maybe (Armour T.Text JWEHeader)
  , _jweUnprotected :: Maybe JWEHeader
  , _jweIv :: Maybe Types.Base64Octets  -- ^ JWE Initialization Vector
  , _jweAad :: Maybe Types.Base64Octets -- ^ JWE AAD
  , _jweCiphertext :: Types.Base64Octets  -- ^ JWE Ciphertext
  , _jweTag :: Maybe Types.Base64Octets  -- ^ JWE Authentication Tag
  , _jweRecipients :: [JWERecipient]
  }

instance FromJSON JWE where
  parseJSON =
    withObject "JWE JSON Serialization" $ \o -> JWE
      <$> o .:? "protected"
      <*> o .:? "unprotected"
      <*> o .:? "iv"
      <*> o .:? "aad"
      <*> o .: "ciphertext"
      <*> o .:? "tag"
      <*> o .: "recipients"
  -- TODO flattened serialization
