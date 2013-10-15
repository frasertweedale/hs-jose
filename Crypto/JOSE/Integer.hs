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

module Crypto.JOSE.Integer where

import Control.Applicative
import Data.List (unfoldr)
import Data.Tuple (swap)
import Data.Word

import qualified Codec.Binary.Base64Url as B64
import Data.Aeson
import qualified Data.Text as T


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
