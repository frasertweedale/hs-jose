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

{-|

Data types for the JOSE library.

-}
module Crypto.JOSE.Types
  (
    Base64Integer(..)
  , SizedBase64Integer(..)
  , checkSize
  , Base64UrlString(..)
  , Base64Octets(..)
  , Base64SHA1(..)
  , Base64SHA256(..)
  , Base64X509(..)
  , URI
  ) where

import Control.Applicative

import Data.Aeson
import Data.Aeson.Types (Parser)
import Data.Byteable
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64.URL as B64U
import Data.X509
import Network.URI (URI)

import Crypto.JOSE.Types.Internal
import Crypto.JOSE.Types.Orphans ()


-- | A base64url encoded octet sequence interpreted as an integer.
--
newtype Base64Integer = Base64Integer Integer
  deriving (Eq, Show)

instance FromJSON Base64Integer where
  parseJSON = withText "base64url integer" $ parseB64Url $
    pure . Base64Integer . bsToInteger

instance ToJSON Base64Integer where
  toJSON (Base64Integer x) = encodeB64Url $ integerToBS x


-- | A base64url encoded octet sequence interpreted as an integer
-- and where the number of octets carries explicit bit-length
-- information.
--
data SizedBase64Integer = SizedBase64Integer Int Integer
  deriving (Eq, Show)

instance FromJSON SizedBase64Integer where
  parseJSON = withText "full size base64url integer" $ parseB64Url (\bytes ->
    pure $ SizedBase64Integer (B.length bytes) (bsToInteger bytes))

instance ToJSON SizedBase64Integer where
  toJSON (SizedBase64Integer s x) = encodeB64Url $ zeroPad $ integerToBS x
    where zeroPad xs = B.replicate (s - B.length xs) 0 `B.append` xs

-- | Parsed a 'SizedBase64Integer' with an expected number of /bytes/.
--
checkSize :: Int -> SizedBase64Integer -> Parser SizedBase64Integer
checkSize n a@(SizedBase64Integer m _) = if n == m
  then return a
  else fail $ "expected " ++ show n ++ " octets, found " ++ show m


-- | A base64url encoded string.  This is used for the JWE
-- /Agreement PartyUInfo/ and /Agreement PartyVInfo/ fields.
--
newtype Base64UrlString = Base64UrlString B.ByteString
  deriving (Eq, Show)

instance FromJSON Base64UrlString where
  parseJSON = withText "base64url string" $ parseB64Url $ pure . Base64UrlString


-- | A base64url encoded octet sequence.  Used for payloads,
-- signatures, symmetric keys, salts, initialisation vectors, etc.
--
newtype Base64Octets = Base64Octets B.ByteString
  deriving (Eq, Show)

instance Byteable Base64Octets where
  toBytes (Base64Octets s) = unpad $ B64U.encode s

instance FromJSON Base64Octets where
  parseJSON = withText "Base64Octets" $ parseB64Url (pure . Base64Octets)

instance ToJSON Base64Octets where
  toJSON (Base64Octets bytes) = encodeB64Url bytes


-- | A base64url encoded SHA-1 digest.  Used for X.509 certificate
-- thumbprints.
--
newtype Base64SHA1 = Base64SHA1 B.ByteString
  deriving (Eq, Show)

instance FromJSON Base64SHA1 where
  parseJSON = withText "base64url SHA-1" $ parseB64Url (\bytes ->
    case B.length bytes of
      20 -> pure $ Base64SHA1 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA1 where
  toJSON (Base64SHA1 bytes) = encodeB64Url bytes


-- | A base64url encoded SHA-256 digest.  Used for X.509 certificate
-- thumbprints.
--
newtype Base64SHA256 = Base64SHA256 B.ByteString
  deriving (Eq, Show)

instance FromJSON Base64SHA256 where
  parseJSON = withText "base64url SHA-256" $ parseB64Url (\bytes ->
    case B.length bytes of
      32 -> pure $ Base64SHA256 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA256 where
  toJSON (Base64SHA256 bytes) = encodeB64Url bytes


-- | A base64 encoded X.509 certificate.
--
newtype Base64X509 = Base64X509 SignedCertificate
  deriving (Eq, Show)

instance FromJSON Base64X509 where
  parseJSON = withText "base64url X.509 certificate" $ parseB64 $
    either fail (pure . Base64X509) . decodeSignedCertificate

instance ToJSON Base64X509 where
  toJSON (Base64X509 x509) = encodeB64 $ encodeSignedObject x509
