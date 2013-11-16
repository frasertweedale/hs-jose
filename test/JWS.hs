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
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.HashMap.Strict as M
import Test.Hspec

import Crypto.JOSE.Compact
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
  appendixA2Spec
  appendixA5Spec
  appendixA6Spec

critSpec = describe "JWS §4.1.10. \"crit\" Header Parameter; parsing" $ do
  it "parses from JSON correctly" $ do
    decode good `shouldBe`
      Just (CritParameters $ M.fromList [("exp", Number (I 1363284000))])
    decode "{}" `shouldBe` (Nothing :: Maybe CritParameters)
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
    decode s `shouldBe` Just ((algHeader JWA.JWS.ES256) { headerCrit = Just critValue })
    where
      s = "{\"alg\":\"ES256\",\"crit\":[\"exp\"],\"exp\":1363284000}"
      critValue = CritParameters $ M.fromList [("exp", Number (I 1363284000))]


headerSpec = describe "(unencoded) Header" $ do
  it "parses from JSON correctly" $
    let
      headerJSON = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
      typValue = Just "JWT"
    in
      eitherDecode headerJSON
        `shouldBe` Right ((algHeader JWA.JWS.HS256) { headerTyp = typValue })

  it "parses signature correctly" $
    let
      sigJSON =
        "{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\
        \ \"header\":{\"kid\":\"2010-12-29\"},\
        \ \"signature\":\"\"}"
      header = (algHeader JWA.JWS.RS256) { headerKid = Just "2010-12-29" }
      sig = Signature header (Types.Base64Octets "")
    in
      eitherDecode sigJSON `shouldBe` Right sig


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
    decodeCompact compactJWS `shouldBe` Right jws

  it "round-trips correctly" $ do
    (encodeCompact jws >>= decodeCompact) `shouldBe` Right jws

  it "computes the HMAC correctly" $
    sign' alg keyMaterial signingInput `shouldBe` BS.pack macOctets

  it "validates the JWS correctly" $ do
    fmap (validate jwk) (decodeCompact compactJWS) `shouldBe` Right True

  where
    signingInput = "\
      \eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    compactJWS = signingInput `BSL.append` "\
      \.\
      \dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    jws = JWS examplePayload [signature]
    signature = Signature h (Types.Base64Octets mac)
    alg = JWA.JWS.HS256
    h = (algHeader alg) { headerTyp = Just "JWT" }
    mac = foldr BS.cons BS.empty macOctets
    macOctets =
      [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
      187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
      132, 141, 121]
    keyMaterial = OctKeyMaterial Oct octKeyMaterial
    jwk = materialJWK keyMaterial
    octKeyMaterial = Types.Base64Octets $ foldr BS.cons BS.empty
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]


appendixA2Spec = describe "JWS A.2. Example JWS using RSASSA-PKCS-v1_5 SHA-256" $ do
  it "computes the signature correctly" $
    sign' JWA.JWS.RS256 jwk signingInput `shouldBe` sig

  it "validates the signature correctly" $
    validate' JWA.JWS.RS256 jwk signingInput sig `shouldBe` True

  where
    signingInput = "\
      \eyJhbGciOiJSUzI1NiJ9\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    jwk = fromJust $ decode "\
      \{\"kty\":\"RSA\",\
      \ \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx\
            \HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs\
            \D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH\
            \SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV\
            \MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8\
            \NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\",\
      \ \"e\":\"AQAB\",\
      \ \"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I\
            \jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0\
            \BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn\
            \439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT\
            \CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh\
            \BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"\
      \}"
    sig = BS.pack sigOctets
    sigOctets =
      [112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69,
      243, 65, 6, 174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125,
      131, 101, 109, 66, 10, 253, 60, 150, 238, 221, 115, 162, 102, 62, 81,
      102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69,
      229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219,
      61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
      16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31,
      190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244,
      74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1,
      48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129,
      253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239,
      177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
      173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157,
      105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69,
      34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202,
      234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90,
      193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67, 208, 25, 238,
      251, 71]


appendixA5Spec = describe "JWS A.5.  Example Plaintext JWS" $ do
  it "encodes the correct JWS" $ do
    encodeCompact jws `shouldBe` Right exampleJWS

  it "decodes the correct JWS" $ do
    decodeCompact exampleJWS `shouldBe` Right jws

  where
    jws = sign (JWS examplePayload []) (algHeader JWA.JWS.None) undefined
    exampleJWS = "eyJhbGciOiJub25lIn0\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ\
      \."


appendixA6Spec = describe "JWS A.6.  Example JWS Using JWS JSON Serialization" $
  it "decodes the correct JWS" $
    eitherDecode exampleJWS `shouldBe` Right jws

  where
    jws = JWS examplePayload [sig1, sig2]
    sig1 = Signature h1 (Types.Base64Octets mac1)
    h1 = (algHeader JWA.JWS.RS256) { headerKid = Just "2010-12-29" }
    mac1 = foldr BS.cons BS.empty
      [112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69,
      243, 65, 6, 174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125,
      131, 101, 109, 66, 10, 253, 60, 150, 238, 221, 115, 162, 102, 62, 81,
      102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69,
      229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219,
      61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
      16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31,
      190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244,
      74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1,
      48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129,
      253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239,
      177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
      173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157,
      105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69,
      34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202,
      234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90,
      193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67, 208, 25, 238,
      251, 71]
    sig2 = Signature h2 (Types.Base64Octets mac2)
    h2 = (algHeader JWA.JWS.ES256) { headerKid = Just "e9bc097a-ce51-4036-9562-d2ade882db0d" }
    mac2 = B64U.decodeLenient
      "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA\
      \pmWQxfKTUJqPP3-Kg6NU1Q"

    exampleJWS = "\
      \{\"payload\":\
      \  \"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF\
          \tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\",\
      \ \"signatures\":[\
      \   {\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\
      \    \"header\":\
      \     {\"kid\":\"2010-12-29\"},\
      \    \"signature\":\
      \     \"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ\
             \mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb\
             \KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl\
             \b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES\
             \c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX\
             \LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw\"},\
      \   {\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\
      \    \"header\":\
      \     {\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\
      \    \"signature\":\
      \     \"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS\
            \lSApmWQxfKTUJqPP3-Kg6NU1Q\"}]\
      \}"
