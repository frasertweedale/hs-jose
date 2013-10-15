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

{-# LANGUAGE FlexibleInstances #-}

module Crypto.JOSE.Types where

import Control.Applicative
import Data.Char
import Data.List (unfoldr)
import Data.String
import Data.Tuple (swap)
import Data.Word

import qualified Codec.Binary.Base64
import qualified Codec.Binary.Base64Url as B64
import Data.Aeson
import qualified Data.ByteString.Lazy as BS
import Data.Certificate.X509
import qualified Data.Text as T
import Network.URI


pad s
  | length s `mod` 4 == 0 = s
  | otherwise             = pad (s ++ "=")

unpad = reverse . dropWhile (== '=') . reverse


wordsToInteger :: [Word8] -> Integer
wordsToInteger = foldl (\acc x -> acc * 256 + toInteger x) 0

integerToWords :: Integer -> [Word8]
integerToWords = map fromIntegral . reverse . unfoldr (fmap swap . f)
  where f x = if x == 0 then Nothing else Just (quotRem x  256)


data Base64Integer = Base64Integer Integer
  deriving (Eq, Show)

instance FromJSON Base64Integer where
  parseJSON = withText "base64url integer" (\s ->
    case B64.decode $ T.unpack s of
      Nothing -> fail "invalid base64 integer"
      Just bytes -> pure $ Base64Integer $ wordsToInteger bytes)

instance ToJSON Base64Integer where
  toJSON (Base64Integer x) = String $ T.pack $ B64.encode $ integerToWords x


data SizedBase64Integer = SizedBase64Integer Int Integer
  deriving (Eq, Show)

instance FromJSON SizedBase64Integer where
  parseJSON = withText "full size base64url integer" (\s ->
    case B64.decode $ T.unpack s of
      Nothing -> fail "invalid base64 integer"
      Just bytes -> pure $ SizedBase64Integer size val where
       size = length bytes
       val = wordsToInteger bytes)

instance ToJSON SizedBase64Integer where
  toJSON (SizedBase64Integer s x) = String $ T.pack
    $ dropPadding $ B64.encode
    $ zeroPad $ integerToWords x
    where
      zeroPad xs = replicate (s - length xs) 0 ++ xs
      dropPadding = reverse . dropWhile (== '=') . reverse


data Base64UrlString = Base64UrlString String
  deriving (Eq, Show)

instance FromJSON Base64UrlString where
  parseJSON = withText "base64url string" (\s ->
    case B64.decode $ pad $ T.unpack s of
      Nothing -> fail "invalid base64url encoded string"
      -- probably wrong; really want to do a proper UTF-8 decode of bytes
      Just bytes -> pure $ Base64UrlString $ map (chr . fromIntegral) bytes)


data Base64Octets = Base64Octets [Word8]
  deriving (Eq, Show)

instance FromJSON Base64Octets where
  parseJSON = withText "Base64Octets" (\s ->
    case B64.decode $ pad $ T.unpack s of
      Nothing -> fail "invalid base64 encoded octets"
      Just bytes -> pure $ Base64Octets bytes)

instance ToJSON Base64Octets where
  toJSON (Base64Octets bytes) = String $ T.pack $ unpad $ B64.encode bytes


data Base64SHA1 = Base64SHA1 [Word8]
  deriving (Eq, Show)

instance FromJSON Base64SHA1 where
  parseJSON = withText "base64url SHA-1" (\s ->
    case B64.decode $ pad $ T.unpack s of
      Nothing -> fail "invalid base64url SHA-1"
      Just bytes
        | length bytes == 20 -> pure $ Base64SHA1 bytes
        | otherwise -> fail "incorrect number of bytes")

instance ToJSON Base64SHA1 where
  toJSON (Base64SHA1 bytes) = String $ T.pack $ unpad $ B64.encode bytes


data Base64X509 = Base64X509 X509
  deriving (Eq, Show)

instance FromJSON Base64X509 where
  parseJSON = withText "base64url X.509 certificate" (\s ->
    case Codec.Binary.Base64.decode $ pad $ T.unpack s of
      Nothing -> fail "invalid base64 X.509 certificate"
      Just bytes -> case decodeCertificate $ BS.pack bytes of
        Left s -> fail $ "failed to decode X.509 certificate" ++ s
        Right x509 -> pure $ Base64X509 x509)

instance ToJSON Base64X509 where
  toJSON (Base64X509 x509) = String $ T.pack $ Codec.Binary.Base64.encode
    $ BS.unpack $ encodeCertificate x509


instance FromJSON URI where
  parseJSON = withText "URI" ((maybe (fail "not a URI") pure) . parseURI . T.unpack)

instance ToJSON URI where
  toJSON uri = String $ T.pack $ show uri


instance IsString [Word8] where
  fromString = map (fromIntegral . ord)
