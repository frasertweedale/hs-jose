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

module JOSE.Integer where

import Control.Applicative
import Data.Word

import qualified Codec.Binary.Base64Url as B64
import Data.Aeson
import qualified Data.Text as T


wordsToInteger :: [Word8] -> Integer
wordsToInteger = foldl (\acc x -> acc * 256 + toInteger x) 0


data Base64Integer = Base64Integer Integer
  deriving (Show)

instance FromJSON Base64Integer where
  parseJSON (String s) = case B64.decode $ T.unpack s of
    Nothing -> fail "invalid base64 integer"
    Just bytes -> pure $ Base64Integer $ wordsToInteger bytes
  parseJSON _ = empty


data SizedBase64Integer = SizedBase64Integer Int Integer
  deriving (Show)

instance FromJSON SizedBase64Integer where
  parseJSON (String s) = case B64.decode $ T.unpack s of
    Nothing -> fail "invalid base64 integer"
    Just bytes -> pure $ SizedBase64Integer size val where
     size = length bytes * 8
     val = wordsToInteger bytes
  parseJSON _ = empty
