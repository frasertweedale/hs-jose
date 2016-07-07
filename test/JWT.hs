-- Copyright (C) 2013, 2014, 2015, 2016  Fraser Tweedale
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

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeSynonymInstances #-}

module JWT where

import Data.Maybe

import Control.Lens
import Control.Monad.Reader (MonadReader(..), Reader, runReader)
import Control.Monad.Time (MonadTime(..))
import Data.Aeson hiding ((.=))
import Data.HashMap.Strict (insert)
import qualified Data.Set as S
import Data.Time
import Network.URI (parseURI)
import Safe (headMay)
import Test.Hspec

import Crypto.JOSE
import Crypto.JWT


intDate :: String -> Maybe NumericDate
intDate = fmap NumericDate . parseTimeM True defaultTimeLocale "%F %T"

utcTime :: String -> UTCTime
utcTime = fromJust . parseTimeM True defaultTimeLocale "%F %T"

exampleClaimsSet :: ClaimsSet
exampleClaimsSet = emptyClaimsSet
  & claimIss .~ Just (fromString "joe")
  & claimExp .~ intDate "2011-03-22 18:43:00"
  & over unregisteredClaims (insert "http://example.com/is_root" (Bool True))
  & addClaim "http://example.com/is_root" (Bool True)

instance MonadTime (Reader UTCTime) where
  currentTime = ask

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

    describe "when the current time is prior to the Expiration Time" $
      let
        now = utcTime "2010-01-01 00:00:00"
      in
        it "can be validated" $
          runReader (validateClaimsSet conf exampleClaimsSet) now `shouldBe` True

    describe "when the current time is exactly the Expiration Time" $
      let
        now = utcTime "2011-03-22 18:43:00"
      in
        it "cannot be validated" $
          runReader (validateClaimsSet conf exampleClaimsSet) now `shouldBe` False

    describe "when the current time is after the Expiration Time" $
      let
        now = utcTime "2011-03-22 18:43:01"  -- 1s after expiry
      in do
        it "cannot be validated" $
          runReader (validateClaimsSet conf exampleClaimsSet) now
            `shouldBe` False
        it "cannot be validated if nonzero skew tolerance < delta" $
          let conf' = conf >> validationAllowedSkew .= 1
          in runReader (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` False
        it "can be validated if nonzero skew tolerance = delta" $
          let conf' = conf >> validationAllowedSkew .= 2
          in runReader (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` True
        it "can be validated if nonzero skew tolerance > delta" $
          let conf' = conf >> validationAllowedSkew .= 3
          in runReader (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` True
        it "can be validated if negative skew tolerance = delta" $
          let conf' = conf >> validationAllowedSkew .= 3
          in runReader (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` True

    describe "with a Not Before claim" $
      let
        claimsSet = emptyClaimsSet & claimNbf .~ intDate "2016-07-05 17:37:22"
      in do
        describe "when the current time is prior to the Not Before claim" $
          let
            now = utcTime "2016-07-05 17:37:20" -- 2s before nbf
          in do
            it "cannot be validated" $
              runReader (validateClaimsSet conf claimsSet) now
                `shouldBe` False
            it "cannot be validated if nonzero skew tolerance < delta" $
              let conf' = conf >> validationAllowedSkew .= 1
              in runReader (validateClaimsSet conf' claimsSet) now
                `shouldBe` False
            it "can be validated if nonzero skew tolerance = delta" $
              let conf' = conf >> validationAllowedSkew .= 2
              in runReader (validateClaimsSet conf' claimsSet) now
                `shouldBe` True
            it "can be validated if nonzero skew tolerance > delta" $
              let conf' = conf >> validationAllowedSkew .= 3
              in runReader (validateClaimsSet conf' claimsSet) now
                `shouldBe` True
            it "can be validated if negative skew tolerance = delta" $
              let conf' = conf >> validationAllowedSkew .= 3
              in runReader (validateClaimsSet conf' claimsSet) now
                `shouldBe` True

        describe "when the current time is exactly equal to the Not Before claim" $
          let
            now = utcTime "2016-07-05 17:37:22"
          in
            it "can be validated" $
              runReader (validateClaimsSet conf claimsSet) now `shouldBe` True

        describe "when the current time is after the Not Before claim" $
          let
            now = utcTime "2017-01-01 00:00:00"
          in
            it "can be validated" $
              runReader (validateClaimsSet conf claimsSet) now `shouldBe` True

    describe "with Expiration Time and Not Before claims" $
      let
        claimsSet = emptyClaimsSet & claimExp .~ intDate "2011-03-22 18:43:00"
                                   & claimNbf .~ intDate "2011-03-20 17:37:22"
      in do
        describe "when the current time is prior to the Not Before claim" $
          let
            now = utcTime "2011-03-18 00:00:00"
          in
            it "cannot be validated" $
              runReader (validateClaimsSet conf claimsSet) now `shouldBe` False

        describe "when the current time is exactly equal to the Not Before claim" $
          let
            now = utcTime "2011-03-20 17:37:22"
          in
            it "can be validated" $
              runReader (validateClaimsSet conf claimsSet) now `shouldBe` True

        describe "when the current time is between the Not Before and Expiration Time claims" $
          let
            now = utcTime "2011-03-21 18:00:00"
          in
            it "can be validated" $
              runReader (validateClaimsSet conf claimsSet) now `shouldBe` True

        describe "when the current time is exactly the Expiration Time" $
          let
            now = utcTime "2011-03-22 18:43:00"
          in
            it "cannot be validated" $
              runReader (validateClaimsSet conf claimsSet) now `shouldBe` False

        describe "when the current time is after the Expiration Time claim" $
          let
            now = utcTime "2011-03-24 00:00:00"
          in
            it "cannot be validated" $
              runReader (validateClaimsSet conf claimsSet) now `shouldBe` False

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
    let
      exampleJWT = "eyJhbGciOiJub25lIn0\
        \.\
        \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
        \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ\
        \."
      jwt = decodeCompact exampleJWT
      k = fromJust $ decode "{\"kty\":\"oct\",\"k\":\"\"}"
    in do
      describe "when the current time is prior to the Expiration Time" $
        let
          now = utcTime "2010-01-01 00:00:00"
          run = flip runReader now
        in
          it "can be decoded and validated" $ do
            fmap jwtClaimsSet jwt `shouldBe` Right exampleClaimsSet
            fmap (run . validateJWSJWT conf k) jwt `shouldBe` Right True

      describe "when the current time is after the Expiration Time" $
        let
          now = utcTime "2012-01-01 00:00:00"
          run = flip runReader now
        in
          it "can be decoded, but not validated" $ do
            fmap jwtClaimsSet jwt `shouldBe` Right exampleClaimsSet
            fmap (run . validateJWSJWT conf k) jwt `shouldBe` Right False
              where conf = validationAlgorithms .= S.singleton None
