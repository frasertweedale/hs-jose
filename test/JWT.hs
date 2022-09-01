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

module JWT where

import Data.Maybe
import Data.Monoid ((<>))

import qualified Data.ByteString.Lazy as L
import Control.Lens
import Control.Lens.Extras (is)
import Control.Monad.Trans (liftIO)
import Control.Monad.Reader (runReaderT)
import Data.Aeson hiding ((.=))
import qualified Data.Aeson.KeyMap as M
import qualified Data.Set as S
import Data.Time
import Network.URI (parseURI)
import Test.Hspec

import Crypto.JWT


intDate :: String -> Maybe NumericDate
intDate = fmap NumericDate . parseTimeM True defaultTimeLocale "%F %T"

utcTime :: String -> WrappedUTCTime
utcTime = WrappedUTCTime . fromJust . parseTimeM True defaultTimeLocale "%F %T"

--
-- example extended JWT payload type
--

data Super = Super { jwtClaims :: ClaimsSet, isRoot :: Bool }
  deriving (Eq, Show)

instance HasClaimsSet Super where
  claimsSet f s = fmap (\a' -> s { jwtClaims = a' }) (f (jwtClaims s))

instance FromJSON Super where
  parseJSON = withObject "Super" $ \o -> Super
    <$> parseJSON (Object o)
    <*> o .: "http://example.com/is_root"

instance ToJSON Super where
  toJSON s =
    ins "http://example.com/is_root" (isRoot s) (toJSON (jwtClaims s))
    where
      ins k v (Object o) = Object $ M.insert k (toJSON v) o
      ins _ _ a = a

super :: Super
super = Super
  { jwtClaims = exampleClaimsSet
  , isRoot = True
  }

claimsJSON :: L.ByteString
claimsJSON =
  "{\"iss\":\"joe\",\r\n"
  <> "\"exp\":1300819380,\r\n"
  <> "\"http://example.com/is_root\":true}"

exampleClaimsSet :: ClaimsSet
exampleClaimsSet = emptyClaimsSet
  & claimIss .~ preview stringOrUri ("joe" :: String)
  & claimExp .~ intDate "2011-03-22 18:43:00"
  & addClaim "http://example.com/is_root" (Bool True)

spec :: Spec
spec = do
  let conf = set algorithms (S.singleton None)
              (defaultJWTValidationSettings (const False))
      headMay []    = Nothing
      headMay (h:_) = Just h

  describe "JWT Claims Set" $ do
    it "parses from JSON correctly" $ do
      decode claimsJSON `shouldBe` Just exampleClaimsSet
      decode claimsJSON `shouldBe` Just super

    it "JWT round-trip (sign, serialise, decode, verify)" $ do
      let
        claims = emptyClaimsSet
        valConf = defaultJWTValidationSettings (const True)
      k <- genJWK $ RSAGenParam 256
      res <- runJOSE $ do
        token <- signClaims k (newJWSHeader ((), RS512)) claims
        token' <- decodeCompact . encodeCompact $ token
        liftIO $ token' `shouldBe` token
        claims' <- verifyClaims valConf k token'
        liftIO $ claims' `shouldBe` claims
      either (error . show) return (res :: Either JWTError ()) :: IO ()

    it "JWT round-trip (sign, serialise, decode, verify) [extended payload type]" $ do
      let
        claims = emptyClaimsSet
        valConf = defaultJWTValidationSettings (const True)
        now = utcTime "2010-01-01 00:00:00"
      k <- genJWK $ RSAGenParam 256
      res <- runJOSE $ do
        token <- signJWT k (newJWSHeader ((), RS512)) super
        token' <- decodeCompact . encodeCompact $ token
        liftIO $ token' `shouldBe` token
        claims' <- runReaderT (verifyJWT valConf k token') now
        liftIO $ claims' `shouldBe` super
      either (error . show) return (res :: Either JWTError ()) :: IO ()

    it "formats to a parsable and equal value" $ do
      decode (encode exampleClaimsSet) `shouldBe` Just exampleClaimsSet
      decode (encode super) `shouldBe` Just super

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

  describe "RFC 7519 §3.1.  Example JWT" $
    it "verifies JWT" $ do
      let
        exampleJWT =
          "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
          <> "."
          <> "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
          <> "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
          <> "."
          <> "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        k = fromOctets
          [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
           230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
           210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
           192,205,154,245,103,208,128,163]
        now = utcTime "2010-01-01 00:00:00"
        settings = defaultJWTValidationSettings (const True)
      runReaderT (decodeCompact exampleJWT >>= verifyClaims settings k) now
        `shouldBe` (Right exampleClaimsSet :: Either JWTError ClaimsSet)
      runReaderT (decodeCompact exampleJWT >>= verifyJWT settings k) now
        `shouldBe` (Right super :: Either JWTError Super)

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
