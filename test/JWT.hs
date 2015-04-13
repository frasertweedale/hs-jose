-- Copyright (C) 2013, 2014  Fraser Tweedale
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

{-# LANGUAGE OverloadedStrings #-}

module JWT where

import Data.Maybe

import Control.Lens
import Data.Aeson
import Data.Default.Class (def)
import Data.HashMap.Strict (insert)
import Data.Time
import Network.URI (parseURI)
import Safe (headMay)
import Test.Hspec

import Crypto.JOSE
import Crypto.JWT


intDate :: String -> Maybe NumericDate
intDate = fmap NumericDate . parseTimeM True defaultTimeLocale "%F %T"

exampleClaimsSet :: ClaimsSet
exampleClaimsSet = emptyClaimsSet
  & claimIss .~ Just (fromString "joe")
  & claimExp .~ intDate "2011-03-22 18:43:00"
  & over unregisteredClaims (insert "http://example.com/is_root" (Bool True))
  & addClaim "http://example.com/is_root" (Bool True)

spec :: Spec
spec = do
  describe "JWT Claims Set" $ do
    it "parses from JSON correctly" $
      let
        claimsJSON = "\
          \{\"iss\":\"joe\",\r\n\
          \ \"exp\":1300819380,\r\n\
          \ \"http://example.com/is_root\":true}"
      in
        decode claimsJSON `shouldBe` Just exampleClaimsSet

    it "formats to a parsable and equal value" $
      decode (encode exampleClaimsSet) `shouldBe` Just exampleClaimsSet

  describe "StringOrURI" $
    it "parses from JSON correctly" $ do
      (decode "[\"foo\"]" >>= headMay >>= getString) `shouldBe` Just "foo"
      (decode "[\"http://example.com\"]" >>= headMay >>= getURI)
        `shouldBe` parseURI "http://example.com"
      decode "[\":\"]" `shouldBe` (Nothing :: Maybe [StringOrURI])
      decode "[12345]" `shouldBe` (Nothing :: Maybe [StringOrURI])

  describe "NumericDate" $
    it "parses from JSON correctly" $ do
      decode "[0]"          `shouldBe` fmap (:[]) (intDate "1970-01-01 00:00:00")
      decode "[1382245921]" `shouldBe` fmap (:[]) (intDate "2013-10-20 05:12:01")
      decode "[\"notnum\"]"       `shouldBe` (Nothing :: Maybe [NumericDate])

  describe "§6.1.  Example Unsecured JWT" $
    it "can be decoded and validated" $
      let
        exampleJWT = "eyJhbGciOiJub25lIn0\
          \.\
          \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
          \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ\
          \."
        jwt = decodeCompact exampleJWT
        k = fromJust $ decode "{\"kty\":\"oct\",\"k\":\"\"}"
      in do
        fmap jwtClaimsSet jwt `shouldBe` Right exampleClaimsSet
        fmap (validateJWSJWT algs def k) jwt `shouldBe` Right True
          where algs = ValidationAlgorithms [None]
