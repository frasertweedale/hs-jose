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

module Crypto.JOSE.Types where

import Control.Applicative
import Data.Char
import Data.Word

import qualified Codec.Binary.Base64Url as B64
import Data.Aeson
import qualified Data.Text as T
import Network.URI


equalsPad s
  | length s `mod` 4 == 0 = s
  | otherwise             = equalsPad (s ++ "=")


data Base64UrlString = Base64UrlString String
  deriving (Eq, Show)

instance FromJSON Base64UrlString where
  parseJSON (String s) = case B64.decode $ equalsPad $ T.unpack s of
      Nothing -> fail "invalid base64url encoded string"
      -- probably wrong; really want to do a proper UTF-8 decode of bytes
      Just bytes -> pure $ Base64UrlString $ map (chr . fromIntegral) bytes


data Base64Octets = Base64Octets [Word8]
  deriving (Eq, Show)

instance FromJSON Base64Octets where
  parseJSON (String s) = case B64.decode $ equalsPad $ T.unpack s of
    Nothing -> fail "invalid base64 encoded octets"
    Just bytes -> pure $ Base64Octets bytes


data Base64SHA1 = Base64SHA1 [Word8]
  deriving (Eq, Show)

instance FromJSON Base64SHA1 where
  parseJSON (String s) = case B64.decode $ equalsPad $ T.unpack s of
    Nothing -> fail "invalid base64url SHA-1"
    Just bytes
      | length bytes == 20 -> pure $ Base64SHA1 bytes
      | otherwise -> fail "incorrect number of bytes"

instance ToJSON Base64SHA1 where
  toJSON (Base64SHA1 bytes) = String $ T.pack $ dropPadding $ B64.encode bytes
    where
      dropPadding = reverse . dropWhile (== '=') . reverse


instance FromJSON URI where
  parseJSON (String s) = maybe (fail "not a URI") pure $ parseURI $ T.unpack s

instance ToJSON URI where
  toJSON uri = String $ T.pack $ show uri
