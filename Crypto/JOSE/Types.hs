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


pad s = s ++ replicate ((4 - length s `mod` 4) `mod` 4) '='
unpad = reverse . dropWhile (== '=') . reverse

decodeB64 = Codec.Binary.Base64.decode . pad . T.unpack
parseB64 f = maybe (fail "invalid base64url") f . decodeB64
encodeB64 = String . T.pack . Codec.Binary.Base64.encode

decodeB64Url = B64.decode . pad . T.unpack
parseB64Url f = maybe (fail "invalid base64url") f . decodeB64Url
encodeB64Url = String . T.pack . unpad . B64.encode


wordsToInteger :: [Word8] -> Integer
wordsToInteger = foldl (\acc x -> acc * 256 + toInteger x) 0

integerToWords :: Integer -> [Word8]
integerToWords = map fromIntegral . reverse . unfoldr (fmap swap . f)
  where f x = if x == 0 then Nothing else Just (quotRem x  256)


data Base64Integer = Base64Integer Integer
  deriving (Eq, Show)

instance FromJSON Base64Integer where
  parseJSON = withText "base64url integer" $ parseB64Url $
    pure . Base64Integer . wordsToInteger

instance ToJSON Base64Integer where
  toJSON (Base64Integer x) = encodeB64Url $ integerToWords x


data SizedBase64Integer = SizedBase64Integer Int Integer
  deriving (Eq, Show)

instance FromJSON SizedBase64Integer where
  parseJSON = withText "full size base64url integer" $ parseB64Url (\bytes ->
    pure $ SizedBase64Integer (length bytes) (wordsToInteger bytes))

instance ToJSON SizedBase64Integer where
  toJSON (SizedBase64Integer s x) = encodeB64Url $ zeroPad $ integerToWords x
    where zeroPad xs = replicate (s - length xs) 0 ++ xs


data Base64UrlString = Base64UrlString String
  deriving (Eq, Show)

instance FromJSON Base64UrlString where
  parseJSON = withText "base64url string" $ parseB64Url $
    -- probably wrong; really want to do a proper UTF-8 decode of bytes
    pure . Base64UrlString . map (chr . fromIntegral)


data Base64Octets = Base64Octets [Word8]
  deriving (Eq, Show)

instance FromJSON Base64Octets where
  parseJSON = withText "Base64Octets" $ parseB64Url (pure . Base64Octets)

instance ToJSON Base64Octets where
  toJSON (Base64Octets bytes) = encodeB64Url bytes


data Base64SHA1 = Base64SHA1 [Word8]
  deriving (Eq, Show)

instance FromJSON Base64SHA1 where
  parseJSON = withText "base64url SHA-1" $ parseB64Url (\bytes ->
    case length bytes of
      20 -> pure $ Base64SHA1 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA1 where
  toJSON (Base64SHA1 bytes) = encodeB64Url bytes


data Base64X509 = Base64X509 X509
  deriving (Eq, Show)

instance FromJSON Base64X509 where
  parseJSON = let
    l = \s -> fail $ "failed to decode X.509 certificate" ++ s
    r = pure . Base64X509 in
      withText "base64url X.509 certificate" $ parseB64 $
        either l r . decodeCertificate . BS.pack

instance ToJSON Base64X509 where
  toJSON (Base64X509 x509) = encodeB64 $ BS.unpack $ encodeCertificate x509


instance FromJSON URI where
  parseJSON = withText "URI" ((maybe (fail "not a URI") pure) . parseURI . T.unpack)

instance ToJSON URI where
  toJSON uri = String $ T.pack $ show uri


instance IsString [Word8] where
  fromString = map (fromIntegral . ord)
