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

module Crypto.JOSE.Classes where

import qualified Data.ByteString as B

import qualified Crypto.JOSE.JWA.JWS as JWA.JWS

class Key k where
  sign :: JWA.JWS.Alg -> k -> B.ByteString -> B.ByteString
  verify :: JWA.JWS.Alg -> k -> B.ByteString -> B.ByteString -> Bool
