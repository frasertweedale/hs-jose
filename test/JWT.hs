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

{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module JWT where

import Data.Maybe
import Data.Monoid ((<>))

import Control.Lens
import Control.Lens.Extras (is)
import Control.Monad.Except (runExceptT)
import Control.Monad.Trans (liftIO)
import Control.Monad.Reader (MonadReader(..), ReaderT, runReaderT)
import Control.Monad.State (execState)
import Control.Monad.Time (MonadTime(..))
import Data.Aeson hiding ((.=))
import Data.Functor.Identity (runIdentity)
import Data.HashMap.Strict (insert)
import qualified Data.Set as S
import Data.Time
import Network.URI (parseURI)
import Test.Hspec

import Crypto.JWT


intDate :: String -> Maybe NumericDate
intDate = fmap NumericDate . parseTimeM True defaultTimeLocale "%F %T"

utcTime :: String -> UTCTime
utcTime = fromJust . parseTimeM True defaultTimeLocale "%F %T"

exampleClaimsSet :: ClaimsSet
exampleClaimsSet = emptyClaimsSet
  & claimIss .~ preview stringOrUri ("joe" :: String)
  & claimExp .~ intDate "2011-03-22 18:43:00"
  & over unregisteredClaims (insert "http://example.com/is_root" (Bool True))
  & addClaim "http://example.com/is_root" (Bool True)

#if ! MIN_VERSION_monad_time(0,3,0)
instance Monad m => MonadTime (ReaderT UTCTime m) where
  currentTime = ask
#endif

spec :: Spec
spec = do
  let conf = set algorithms (S.singleton None)
              (defaultJWTValidationSettings (const False))
      headMay []    = Nothing
      headMay (h:_) = Just h

  describe "JWT Claims Set" $ do
    it "parses from JSON correctly" $
      let
        claimsJSON =
          "{\"iss\":\"joe\",\r\n"
          <> "\"exp\":1300819380,\r\n"
          <> "\"http://example.com/is_root\":true}"
      in
        decode claimsJSON `shouldBe` Just exampleClaimsSet

    it "JWT compact round-trip" $ do
      jwk <- genJWK $ RSAGenParam 256
      res <- runExceptT $ do
        token <- signClaims jwk (newJWSHeader ((), RS512)) emptyClaimsSet
        token' <- decodeCompact . encodeCompact $ token
        liftIO $ token' `shouldBe` token
      either (error . show) return (res :: Either JWTError ()) :: IO ()

    it "formats to a parsable and equal value" $
      decode (encode exampleClaimsSet) `shouldBe` Just exampleClaimsSet

    describe "with an Expiration Time claim" $ do
      describe "when the current time is prior to the Expiration Time" $ do
        let now = utcTime "2010-01-01 00:00:00"
        it "can be validated" $
          runReaderT (validateClaimsSet conf exampleClaimsSet) now
            `shouldBe` (Right exampleClaimsSet :: Either JWTError ClaimsSet)

      describe "when the current time is exactly the Expiration Time" $ do
        let now = utcTime "2011-03-22 18:43:00"
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf exampleClaimsSet) now
            `shouldBe` Left JWTExpired

      describe "when the current time is after the Expiration Time" $ do
        let now = utcTime "2011-03-22 18:43:01"  -- 1s after expiry
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf exampleClaimsSet) now
            `shouldBe` Left JWTExpired
        it "cannot be validated if nonzero skew tolerance < delta" $
          let conf' = set allowedSkew 1 conf
          in runReaderT (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` Left JWTExpired
        it "can be validated if nonzero skew tolerance = delta" $
          let conf' = set allowedSkew 2 conf
          in runReaderT (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` (Right exampleClaimsSet :: Either JWTError ClaimsSet)
        it "can be validated if nonzero skew tolerance > delta" $
          let conf' = set allowedSkew 3 conf
          in runReaderT (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` (Right exampleClaimsSet :: Either JWTError ClaimsSet)
        it "can be validated if negative skew tolerance = -delta" $
          let conf' = set allowedSkew (-2) conf
          in runReaderT (validateClaimsSet conf' exampleClaimsSet) now
            `shouldBe` (Right exampleClaimsSet :: Either JWTError ClaimsSet)

    describe "with an Issued At claim" $ do
      let claimsSetWithIat = set claimIat (intDate "2011-02-22 18:43:00") emptyClaimsSet

      describe "when the current time is after to the Issued At" $ do
        let now = utcTime "2011-03-01 00:00:00"
        it "can be validated" $
          runReaderT (validateClaimsSet conf claimsSetWithIat) now
            `shouldBe` (Right claimsSetWithIat :: Either JWTError ClaimsSet)

      describe "when the current time is exactly the Issued At" $ do
        let now = utcTime "2011-02-22 18:43:00"
        it "can be validated" $
          runReaderT (validateClaimsSet conf claimsSetWithIat) now
            `shouldBe` (Right claimsSetWithIat :: Either JWTError ClaimsSet)

      describe "when the current time is prior to the Issued At" $ do
        let now = utcTime "2011-02-22 18:42:59"  -- 1s before issued at
        it "cannot be validated if nonzero skew tolerance < delta" $
          let conf' = set allowedSkew 0 conf
          in runReaderT (validateClaimsSet conf' claimsSetWithIat) now
            `shouldBe` Left JWTIssuedAtFuture
        it "can be validated if nonzero skew tolerance < delta but validation is off" $
          let conf' = set checkIssuedAt False conf
          in runReaderT (validateClaimsSet conf' claimsSetWithIat) now
            `shouldBe` (Right claimsSetWithIat :: Either JWTError ClaimsSet)
        it "can be validated if nonzero skew tolerance = delta" $
          let conf' = set allowedSkew 1 conf
          in runReaderT (validateClaimsSet conf' claimsSetWithIat) now
            `shouldBe` (Right claimsSetWithIat :: Either JWTError ClaimsSet)
        it "can be validated if nonzero skew tolerance > delta" $
          let conf' = set allowedSkew 2 conf
          in runReaderT (validateClaimsSet conf' claimsSetWithIat) now
            `shouldBe` (Right claimsSetWithIat :: Either JWTError ClaimsSet)
        it "can be validated if negative skew tolerance = -delta" $
          let conf' = set allowedSkew (-1) conf
          in runReaderT (validateClaimsSet conf' claimsSetWithIat) now
            `shouldBe` (Right claimsSetWithIat :: Either JWTError ClaimsSet)

    describe "with a Not Before claim" $ do
      let
        claimsSet = emptyClaimsSet & claimNbf .~ intDate "2016-07-05 17:37:22"
      describe "when the current time is prior to the Not Before claim" $ do
        let now = utcTime "2016-07-05 17:37:20" -- 2s before nbf
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf claimsSet) now
            `shouldBe` Left JWTNotYetValid
        it "cannot be validated if nonzero skew tolerance < delta" $
          let conf' = set allowedSkew 1 conf
          in runReaderT (validateClaimsSet conf' claimsSet) now
            `shouldBe` Left JWTNotYetValid
        it "can be validated if nonzero skew tolerance = delta" $
          let conf' = set allowedSkew 2 conf
          in runReaderT (validateClaimsSet conf' claimsSet) now
            `shouldBe` (Right claimsSet :: Either JWTError ClaimsSet)
        it "can be validated if nonzero skew tolerance > delta" $
          let conf' = set allowedSkew 3 conf
          in runReaderT (validateClaimsSet conf' claimsSet) now
            `shouldBe` (Right claimsSet :: Either JWTError ClaimsSet)
        it "can be validated if negative skew tolerance = -delta" $
          let conf' = set allowedSkew (-2) conf
          in runReaderT (validateClaimsSet conf' claimsSet) now
            `shouldBe` (Right claimsSet :: Either JWTError ClaimsSet)

      describe "when the current time is exactly equal to the Not Before claim" $
        it "can be validated" $
          runReaderT (validateClaimsSet conf claimsSet) (utcTime "2016-07-05 17:37:22")
            `shouldBe` (Right claimsSet :: Either JWTError ClaimsSet)

      describe "when the current time is after the Not Before claim" $
        it "can be validated" $
          runReaderT (validateClaimsSet conf claimsSet) (utcTime "2017-01-01 00:00:00")
            `shouldBe` (Right claimsSet :: Either JWTError ClaimsSet)

    describe "with Expiration Time and Not Before claims" $ do
      let
        claimsSet = emptyClaimsSet & claimExp .~ intDate "2011-03-22 18:43:00"
                                   & claimNbf .~ intDate "2011-03-20 17:37:22"
      describe "when the current time is prior to the Not Before claim" $
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf claimsSet) (utcTime "2011-03-18 00:00:00")
            `shouldBe` Left JWTNotYetValid
      describe "when the current time is exactly equal to the Not Before claim" $
        it "can be validated" $
          runReaderT (validateClaimsSet conf claimsSet) (utcTime "2011-03-20 17:37:22")
            `shouldBe` (Right claimsSet :: Either JWTError ClaimsSet)
      describe "when the current time is between the Not Before and Expiration Time claims" $
        it "can be validated" $
          runReaderT (validateClaimsSet conf claimsSet) (utcTime "2011-03-21 18:00:00")
            `shouldBe` (Right claimsSet :: Either JWTError ClaimsSet)
      describe "when the current time is exactly the Expiration Time" $
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf claimsSet) (utcTime "2011-03-22 18:43:00")
            `shouldBe` Left JWTExpired
      describe "when the current time is after the Expiration Time claim" $
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf claimsSet) (utcTime "2011-03-24 00:00:00")
            `shouldBe` Left JWTExpired

    describe "with an Audience claim" $ do
      let now = utcTime "2001-01-01 00:00:00"
      let conf' = set audiencePredicate (== "baz") conf
      let conf'' = set audiencePredicate (const True) conf
      describe "when claim is nonempty, and default predicate is used" $ do
        let claims = emptyClaimsSet & set claimAud (Just (Audience ["foo"]))
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf claims) now
            `shouldBe` Left JWTNotInAudience
      describe "when claim is nonempty but predicate does not match any value" $ do
        let claims = emptyClaimsSet & set claimAud (Just (Audience ["foo", "bar"]))
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf' claims) now
            `shouldBe` Left JWTNotInAudience
      describe "when claim is nonempty and predicate matches a value" $ do
        let claims = emptyClaimsSet & set claimAud (Just (Audience ["foo", "bar", "baz"]))
        it "can be validated" $
          runReaderT (validateClaimsSet conf' claims) now
            `shouldBe` (Right claims :: Either JWTError ClaimsSet)
      describe "when claim is empty, and predicate is unconditionally true" $ do
        let claims = emptyClaimsSet & set claimAud (Just (Audience []))
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf'' claims) now
            `shouldBe` Left JWTNotInAudience

      describe "when claim has one value" $ do
        let claims = emptyClaimsSet & set claimAud (Just (Audience ["foo"]))
        it "serialises to string" $ encode claims `shouldBe` "{\"aud\":\"foo\"}"
        it "round trips" $ decode (encode claims) `shouldBe` Just claims

    describe "with an Issuer claim" $ do
      let now = utcTime "2001-01-01 00:00:00"
      let conf' = set issuerPredicate (== "baz") conf
      describe "when issuer is nonempty, and predicate is matched" $ do
        let claims = emptyClaimsSet & set claimIss (Just "baz")
        it "can be validated" $
          runReaderT (validateClaimsSet conf' claims) now
            `shouldBe` (Right claims :: Either JWTError ClaimsSet)
      describe "when issuer is nonempty but predicate is not matched" $ do
        let claims = emptyClaimsSet & set claimIss (Just "bar")
        it "cannot be validated" $
          runReaderT (validateClaimsSet conf' claims) now
            `shouldBe` Left JWTNotInIssuer
      describe "when claim is empty, and default predicate is unconditionally true" $ do
        let claims = emptyClaimsSet & set claimIss (Just "")
        it "can be validated" $
          runReaderT (validateClaimsSet conf claims) now
            `shouldBe` (Right claims :: Either JWTError ClaimsSet)

  describe "StringOrURI" $
    it "parses from JSON correctly" $ do
      (decode "[\"foo\"]" >>= headMay >>= preview string) `shouldBe` Just "foo"
      (decode "[\"http://example.com\"]" >>= headMay >>= preview uri)
        `shouldBe` parseURI "http://example.com"
      decode "[\":\"]" `shouldBe` (Nothing :: Maybe [StringOrURI])
      decode "[12345]" `shouldBe` (Nothing :: Maybe [StringOrURI])

  describe "NumericDate" $
    it "parses from JSON correctly" $ do
      decode "[0]"          `shouldBe` fmap (:[]) (intDate "1970-01-01 00:00:00")
      decode "[1382245921]" `shouldBe` fmap (:[]) (intDate "2013-10-20 05:12:01")
      decode "[\"notnum\"]"       `shouldBe` (Nothing :: Maybe [NumericDate])

  describe "RFC 7519 §6.1.  Example Unsecured JWT" $ do
    let
      exampleJWT =
        "eyJhbGciOiJub25lIn0"
        <> "."
        <> "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        <> "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        <> "."
      jwt = decodeCompact exampleJWT
      k = fromJust $ decode "{\"kty\":\"oct\",\"k\":\"\"}" :: JWK

    describe "when the current time is prior to the Expiration Time" $
      it "can be decoded and validated" $
        runReaderT (jwt >>= verifyClaims conf k) (utcTime "2010-01-01 00:00:00")
          `shouldBe` (Right exampleClaimsSet :: Either JWTError ClaimsSet)

    describe "when the current time is after the Expiration Time" $
      it "can be decoded, but not validated" $
        runReaderT (jwt >>= verifyClaims conf k) (utcTime "2012-01-01 00:00:00")
          `shouldBe` Left JWTExpired

    describe "when signature is invalid and token is expired" $
      it "fails on sig validation (claim validation not reached)" $ do
        let jwt' = decodeCompact (exampleJWT <> "badsig")
        (runReaderT (jwt' >>= verifyClaims conf k) (utcTime "2012-01-01 00:00:00")
          :: Either JWTError ClaimsSet)
          `shouldSatisfy` is (_Left . _JWSInvalidSignature)
