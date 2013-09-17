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

module Types where

import Data.Aeson
import Test.Hspec

import Crypto.JOSE.Types

spec = do
  describe "Base64UrlString" $ do
    it "can be read from JSON" $ do
      decode "[\"QWxpY2U\"]" `shouldBe` Just [Base64UrlString "Alice"]
      decode "[\"Qm9i\"]"`shouldBe` Just [Base64UrlString "Bob"]

  describe "Base64Octets" $ do
    it "can be read from JSON" $ do
      decode "[\"AxY8DCtDaGlsbGljb3RoZQ\"]" `shouldBe` Just [Base64Octets iv]
      decode "[\"9hH0vgRfYgPnAHOd8stkvw\"]" `shouldBe` Just [Base64Octets tag]
      where
        iv = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]
        tag = [246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100, 191]
