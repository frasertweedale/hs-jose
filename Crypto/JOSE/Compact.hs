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

{-# LANGUAGE OverloadedStrings #-}

module Crypto.JOSE.Compact where

import qualified Data.ByteString.Lazy as L


class FromCompact a where
  fromCompact :: [L.ByteString] -> Either String a

decodeCompact :: FromCompact a => L.ByteString -> Either String a
decodeCompact = fromCompact . L.split 46


class ToCompact a where
  toCompact :: a -> Either String [L.ByteString]

encodeCompact :: ToCompact a => a -> Either String L.ByteString
encodeCompact = fmap (L.intercalate ".") . toCompact
