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

module JWS where

import Data.Aeson
import Data.Attoparsec.Number
import qualified Data.HashMap.Strict as M
import Test.Hspec

import Crypto.JOSE.JWS

spec = do
  critSpec

critSpec = describe "crit header parameter" $ do
  it "parses from JSON correctly" $ do
    decode good `shouldBe`
      Just (CritParameters $ M.fromList [("exp", Number (I 1363284000))])
    decode "{}" `shouldBe` Just NullCritParameters
    decode missingParam `shouldBe` (Nothing :: Maybe CritParameters)
    decode critNotArray `shouldBe` (Nothing :: Maybe CritParameters)
    decode critValueNotString `shouldBe` (Nothing :: Maybe CritParameters)
    decode critValueNotValid `shouldBe` (Nothing :: Maybe CritParameters)
    where
      good = "{\"alg\":\"ES256\",\"crit\":[\"exp\"],\"exp\":1363284000}"
      missingParam = "{\"alg\":\"ES256\",\"crit\":[\"nope\"]}"
      critNotArray = "{\"alg\":\"ES256\",\"crit\":\"exp\"}"
      critValueNotString = "{\"alg\":\"ES256\",\"crit\":[1234]}"
      critValueNotValid = "{\"alg\":\"ES256\",\"crit\":[\"crit\"]}"
