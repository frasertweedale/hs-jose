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

{-# OPTIONS_GHC -fno-warn-orphans #-}

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.JOSE.Types where

import Control.Applicative
import Data.Tuple (swap)

import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Lazy as BSL
import Data.Certificate.X509
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as E
import Network.URI


objectPairs :: Value -> [Pair]
objectPairs (Object o) = M.toList o
objectPairs _ = []


pad :: T.Text -> T.Text
pad s = s `T.append` T.replicate ((4 - T.length s `mod` 4) `mod` 4) "="

unpad :: T.Text -> T.Text
unpad = T.dropWhileEnd (== '=')


decodeB64 :: T.Text -> Either String BS.ByteString
decodeB64 = B64.decode . E.encodeUtf8

parseB64 :: FromJSON a => (BS.ByteString -> Parser a) -> T.Text -> Parser a
parseB64 f = either fail f . decodeB64

encodeB64 :: BS.ByteString -> Value
encodeB64 = String . E.decodeUtf8 . B64.encode

decodeB64Url :: T.Text -> Either String BS.ByteString
decodeB64Url = B64U.decode . E.encodeUtf8 . pad

parseB64Url :: FromJSON a => (BS.ByteString -> Parser a) -> T.Text -> Parser a
parseB64Url f = either fail f . decodeB64Url

encodeB64Url :: BS.ByteString -> Value
encodeB64Url = String . unpad . E.decodeUtf8 . B64U.encode


bsToInteger :: BS.ByteString -> Integer
bsToInteger = BS.foldl (\acc x -> acc * 256 + toInteger x) 0

integerToBS :: Integer -> BS.ByteString
integerToBS = BS.reverse . BS.unfoldr (fmap swap . f)
  where
    f x = if x == 0 then Nothing else Just (toWord8 $ quotRem x 256)
    toWord8 (seed, x) = (seed, fromIntegral x)


newtype Base64Integer = Base64Integer Integer
  deriving (Eq, Show)

instance FromJSON Base64Integer where
  parseJSON = withText "base64url integer" $ parseB64Url $
    pure . Base64Integer . bsToInteger

instance ToJSON Base64Integer where
  toJSON (Base64Integer x) = encodeB64Url $ integerToBS x


data SizedBase64Integer = SizedBase64Integer Int Integer
  deriving (Eq, Show)

instance FromJSON SizedBase64Integer where
  parseJSON = withText "full size base64url integer" $ parseB64Url (\bytes ->
    pure $ SizedBase64Integer (BS.length bytes) (bsToInteger bytes))

instance ToJSON SizedBase64Integer where
  toJSON (SizedBase64Integer s x) = encodeB64Url $ zeroPad $ integerToBS x
    where zeroPad xs = BS.replicate (s - BS.length xs) 0 `BS.append` xs


newtype Base64UrlString = Base64UrlString BS.ByteString
  deriving (Eq, Show)

instance FromJSON Base64UrlString where
  parseJSON = withText "base64url string" $ parseB64Url $ pure . Base64UrlString


newtype Base64Octets = Base64Octets BS.ByteString
  deriving (Eq, Show)

instance FromJSON Base64Octets where
  parseJSON = withText "Base64Octets" $ parseB64Url (pure . Base64Octets)

instance ToJSON Base64Octets where
  toJSON (Base64Octets bytes) = encodeB64Url bytes


newtype Base64SHA1 = Base64SHA1 BS.ByteString
  deriving (Eq, Show)

instance FromJSON Base64SHA1 where
  parseJSON = withText "base64url SHA-1" $ parseB64Url (\bytes ->
    case BS.length bytes of
      20 -> pure $ Base64SHA1 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA1 where
  toJSON (Base64SHA1 bytes) = encodeB64Url bytes


newtype Base64X509 = Base64X509 X509
  deriving (Eq, Show)

instance FromJSON Base64X509 where
  parseJSON = withText "base64url X.509 certificate" $ parseB64 $
    either fail (pure . Base64X509) . decodeCertificate . BSL.fromStrict

instance ToJSON Base64X509 where
  toJSON (Base64X509 x509) = encodeB64 $ BSL.toStrict $ encodeCertificate x509


instance FromJSON URI where
  parseJSON = withText "URI" (maybe (fail "not a URI") pure . parseURI . T.unpack)

instance ToJSON URI where
  toJSON uri = String $ T.pack $ show uri
