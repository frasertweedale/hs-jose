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

{-|

Data types for the JOSE library.

-}
module Crypto.JOSE.Types where

import Control.Applicative

import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Certificate.X509
import qualified Data.Text as T
import qualified Network.URI

import Crypto.JOSE.Types.Internal


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
    pure $ SizedBase64Integer (BS.length bytes) (bsToInteger bytes))

instance ToJSON SizedBase64Integer where
  toJSON (SizedBase64Integer s x) = encodeB64Url $ zeroPad $ integerToBS x
    where zeroPad xs = BS.replicate (s - BS.length xs) 0 `BS.append` xs


-- | A base64url encoded string.  This is used for the JWE
-- /Agreement PartyUInfo/ and /Agreement PartyVInfo/ fields.
--
newtype Base64UrlString = Base64UrlString BS.ByteString
  deriving (Eq, Show)

instance FromJSON Base64UrlString where
  parseJSON = withText "base64url string" $ parseB64Url $ pure . Base64UrlString


-- | A base64url encoded octet sequence.  Used for payloads,
-- signatures, symmetric keys, salts, initialisation vectors, etc.
--
newtype Base64Octets = Base64Octets BS.ByteString
  deriving (Eq, Show)

instance FromJSON Base64Octets where
  parseJSON = withText "Base64Octets" $ parseB64Url (pure . Base64Octets)

instance ToJSON Base64Octets where
  toJSON (Base64Octets bytes) = encodeB64Url bytes


-- | A base64url encoded SHA-1 digest.  Used for X.509 certificate
-- thumbprints.
--
newtype Base64SHA1 = Base64SHA1 BS.ByteString
  deriving (Eq, Show)

instance FromJSON Base64SHA1 where
  parseJSON = withText "base64url SHA-1" $ parseB64Url (\bytes ->
    case BS.length bytes of
      20 -> pure $ Base64SHA1 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA1 where
  toJSON (Base64SHA1 bytes) = encodeB64Url bytes


-- | A base64url encoded SHA-256 digest.  Used for X.509 certificate
-- thumbprints.
--
newtype Base64SHA256 = Base64SHA256 BS.ByteString
  deriving (Eq, Show)

instance FromJSON Base64SHA256 where
  parseJSON = withText "base64url SHA-256" $ parseB64Url (\bytes ->
    case BS.length bytes of
      32 -> pure $ Base64SHA256 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA256 where
  toJSON (Base64SHA256 bytes) = encodeB64Url bytes


-- | A base64 encoded X.509 certificate.
--
newtype Base64X509 = Base64X509 X509
  deriving (Eq, Show)

instance FromJSON Base64X509 where
  parseJSON = withText "base64url X.509 certificate" $ parseB64 $
    either fail (pure . Base64X509) . decodeCertificate . BSL.fromStrict

instance ToJSON Base64X509 where
  toJSON (Base64X509 x509) = encodeB64 $ BSL.toStrict $ encodeCertificate x509


-- | A URI.  Used for X.509 certificate and JWK Set URLs.
--
newtype URI = URI Network.URI.URI deriving (Eq, Show)

instance FromJSON URI where
  parseJSON = withText "URI" $
    maybe (fail "not a URI") (pure . URI) . Network.URI.parseURI . T.unpack

instance ToJSON URI where
  toJSON (URI uri) = String $ T.pack $ show uri
