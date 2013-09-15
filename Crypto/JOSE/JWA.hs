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

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.JOSE.JWA where

import Control.Applicative

import Data.Aeson
import qualified Data.HashMap.Strict as M

import qualified Crypto.JOSE.JWA.JWE as JWA.JWE
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS


data Alg = JWSAlg JWA.JWS.Alg | JWEAlg JWA.JWE.Alg
  deriving (Show)

instance FromJSON Alg where
  parseJSON (String s) = case M.lookup s JWA.JWE.algMap of
    Just v -> pure $ JWEAlg v
    Nothing -> case M.lookup s JWA.JWS.algMap of
      Just v -> pure $ JWSAlg v
      Nothing -> fail "undefined alg"
  parseJSON _ = empty
