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

import Data.Maybe

import Data.Aeson
import Data.Attoparsec.Number
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict as M
import Test.Hspec

import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.Types as Types

spec = do
  critSpec
  critSpec'
  headerSpec
  appendixA1Spec
  appendixA5Spec

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
    decode s `shouldBe` Just ((algHeader JWA.JWS.ES256) { headerCrit = critValue })
    where
      s = "{\"alg\":\"ES256\",\"crit\":[\"exp\"],\"exp\":1363284000}"
      critValue = CritParameters $ M.fromList [("exp", Number (I 1363284000))]


headerSpec = describe "(unencoded) Header" $ do
  it "parses from JSON correctly" $ do
    decode headerJSON `shouldBe` Just ((algHeader JWA.JWS.HS256) { headerTyp = typValue })
    where
      headerJSON = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
      typValue = Just "JWT"


examplePayload :: Types.Base64Octets
examplePayload = Types.Base64Octets "\
  \{\"iss\":\"joe\",\r\n\
  \ \"exp\":1300819380,\r\n\
  \ \"http://example.com/is_root\":true}"


appendixA1Spec = describe "JWS A.1.  Example JWS using HMAC SHA-256" $ do
  -- can't make aeson encode JSON to exact representation used in
  -- IETF doc, be we can go in reverse and then ensure that the
  -- round-trip checks out
  --
  it "decodes the example to the correct value" $
    decodeCompact compactJWS `shouldBe` Just jws

  it "round-trips correctly" $ do
    maybe (Left "encode failed") eitherDecodeCompact (encodeCompact jws)
      `shouldBe` Right jws
    (encodeCompact jws >>= decodeCompact) `shouldBe` Just jws

  it "computes the HMAC correctly" $
    sign' alg signingInput jwk `shouldBe` BS.pack macOctets

  it "validates the JWS correctly" $ do
    validate jwk jws `shouldBe` True
    validateDecodeCompact jwk compactJWS `shouldBe` True

  where
    signingInput = "\
      \eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    compactJWS = signingInput `BSL.append` "\
      \.\
      \dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    jws = Signatures examplePayload [signature]
    signature = Signature headers (Types.Base64Octets mac)
    headers = Protected (EncodedHeader h { headerRaw = rawHeader })
    rawHeader = Just "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
    alg = JWA.JWS.HS256
    h = (algHeader alg) { headerTyp = Just "JWT" }
    mac = foldr BS.cons BS.empty macOctets
    macOctets =
      [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
      187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
      132, 141, 121]
    jwk = material (OctKeyMaterial Oct octKeyMaterial)
    octKeyMaterial = Types.Base64Octets $ foldr BS.cons BS.empty
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]


appendixA5Spec = describe "JWS A.5.  Example Plaintext JWS" $ do
  it "encodes the correct JWS" $ do
    encodeCompact jws `shouldBe` Just exampleJWS

  it "decodes the correct JWS" $ do
    decodeCompact exampleJWS `shouldBe` Just jws

  where
    headers = Protected (EncodedHeader (algHeader JWA.JWS.None) { headerRaw = rawHeader })
    rawHeader = Just "{\"alg\":\"none\"}"
    inputSignatures = Signatures examplePayload []
    jws = sign inputSignatures headers undefined
    exampleJWS = "eyJhbGciOiJub25lIn0\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ\
      \."
