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
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.Types as Types

spec = do
  critSpec
  critSpec'
  headerSpec
  appendixA1Spec

critSpec = describe "JWS §4.1.10. \"crit\" Header Parameter; parsing" $ do
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

critSpec' = describe "JWS §4.1.10. \"crit\" Header Parameter; full example" $ do
  it "parses from JSON correctly" $ do
    decode s `shouldBe` Just ((algHeader JWA.JWS.ES256) { crit = critValue })
    where
      s = "{\"alg\":\"ES256\",\"crit\":[\"exp\"],\"exp\":1363284000}"
      critValue = CritParameters $ M.fromList [("exp", Number (I 1363284000))]


headerSpec = describe "(unencoded) Header" $ do
  it "parses from JSON correctly" $ do
    decode headerJSON `shouldBe` Just ((algHeader JWA.JWS.HS256) { typ = typValue })
    where
      headerJSON = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
      typValue = Just "JWT"

appendixA1Spec = describe "JWS A.1.1.  Encoding" $ do
  describe "JWS Protected Header" $ do
    it "formats to JSON correctly" $ do
      encode encodedHeader `shouldBe` "\"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\""
  describe "JWS Signing Input" $ do
    it "assembles the signing input correctly" $ do
      signingInput (Protected encodedHeader) payload `shouldBe` "\
        \eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\
        \.\
        \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
        \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  where
    headerJSON = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
    encodedHeader = MockEncodedHeader headerJSON
    payload = Types.Base64Octets "\
      \{\"iss\":\"joe\",\r\n\
      \ \"exp\":1300819380,\r\n\
      \ \"http://example.com/is_root\":true}"
