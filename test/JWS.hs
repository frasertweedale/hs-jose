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

{-# LANGUAGE OverloadedStrings #-}

module JWS where

import Data.Maybe
import Data.Monoid ((<>))

import Control.Lens
import Control.Lens.Extras (is)
import Control.Monad.Except (runExceptT)
import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Base64.URL as B64U
import Test.Hspec

import Crypto.JOSE.Compact
import Crypto.JOSE.Error (Error)
import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS
import Crypto.JOSE.JWS.Internal (Signature(Signature))
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.Types as Types


drg :: ChaChaDRG
drg = drgNewTest (1,2,3,4,5)

spec :: Spec
spec = do
  headerSpec
  appendixA1Spec
  appendixA2Spec
  appendixA3Spec
  appendixA5Spec
  appendixA6Spec


-- Extension of JWSHeader to test "crit" behaviour
--
newtype JWSHeader' = JWSHeader' { unJWSHeader' :: JWSHeader }
  deriving (Eq, Show)
_JWSHeader' :: Iso' JWSHeader' JWSHeader
_JWSHeader' = iso unJWSHeader' JWSHeader'
instance HasJWSHeader JWSHeader' where
  jWSHeader = _JWSHeader'
instance HasParams JWSHeader' where
  parseParamsFor proxy hp hu = JWSHeader' <$> parseParamsFor proxy hp hu
  params (JWSHeader' h) = params h
  extensions = const ["foo"]


headerSpec :: Spec
headerSpec = describe "JWS Header" $ do
  it "parses signature correctly" $
    let
      sigJSON =
        "{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\
        \ \"header\":{\"kid\":\"2010-12-29\"},\
        \ \"signature\":\"\"}"
      h = newJWSHeader (Protected, JWA.JWS.RS256)
        & jwsHeaderKid .~ Just (HeaderParam Unprotected "2010-12-29")
      sig = Signature (Just "eyJhbGciOiJSUzI1NiJ9") h (Types.Base64Octets "")
    in
      eitherDecode sigJSON `shouldBe` Right sig

  it "rejects duplicate headers" $
    let
      -- protected header: {"kid":""}
      s = "{\"protected\":\"eyJraWQiOiIifQ\",\"header\":{\"alg\":\"none\",\"kid\":\"\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader))
        `shouldSatisfy` is _Left

  it "rejects reserved crit parameters" $
    let
      -- protected header: {"crit":["kid"],"kid":""}
      s = "{\"protected\":\"eyJjcml0IjpbImtpZCJdLCJraWQiOiIifQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader))
        `shouldSatisfy` is _Left

  it "rejects unknown crit parameters" $
    let
      -- protected header: {"crit":["foo"],"foo":""}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdLCJmb28iOiIifQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader))
        `shouldSatisfy` is _Left

  it "accepts known crit parameter in protected header" $
    let
      -- protected header: {"crit":["foo"],"foo":""}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdLCJmb28iOiIifQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader'))
        `shouldSatisfy` is _Right

  it "accepts known crit parameter in unprotected header" $
    let
      -- protected header: {"crit":["foo"]}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdfQ\",\"header\":{\"alg\":\"none\",\"foo\":\"\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader'))
        `shouldSatisfy` is _Right

  it "rejects known crit parameter that does not appear in JOSE header" $
    let
      -- protected header: {"crit":["foo"]}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdfQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader'))
        `shouldSatisfy` is _Left

  it "rejects unprotected crit parameters" $
    let
      s = "{\"header\":{\"alg\":\"none\",\"crit\":[\"foo\"],\"foo\":\"\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader'))
        `shouldSatisfy` is _Left

  it "rejects empty crit parameters" $
    let
      -- protected header: {"crit":[]}
      s = "{\"protected\":\"eyJjcml0IjpbXX0\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature JWSHeader'))
        `shouldSatisfy` is _Left


examplePayload :: Types.Base64Octets
examplePayload = Types.Base64Octets "\
  \{\"iss\":\"joe\",\r\n\
  \ \"exp\":1300819380,\r\n\
  \ \"http://example.com/is_root\":true}"


appendixA1Spec :: Spec
appendixA1Spec = describe "JWS A.1.  Example JWS using HMAC SHA-256" $ do
  -- can't make aeson encode JSON to exact representation used in
  -- IETF doc, be we can go in reverse and then ensure that the
  -- round-trip checks out
  --
  it "decodes the example to the correct value" $
    decodeCompact compactJWS
      `shouldBe` (Right jws :: Either Error (JWS JWSHeader))

  it "round-trips correctly" $
    (encodeCompact jws >>= decodeCompact)
      `shouldBe` (Right jws :: Either Error (JWS JWSHeader))

  it "computes the HMAC correctly" $
    fst (withDRG drg $
      runExceptT (sign alg (jwk ^. jwkMaterial) (L.toStrict signingInput')))
      `shouldBe` (Right (BS.pack macOctets) :: Either Error BS.ByteString)

  it "validates the JWS correctly" $
    ( (decodeCompact compactJWS :: Either Error (JWS JWSHeader))
      >>= verifyJWS defaultValidationSettings jwk
    ) `shouldSatisfy` is _Right

  where
    signingInput' = "\
      \eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    compactJWS = signingInput' <> ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    jws = JWS examplePayload [signature]
    signature = Signature encodedProtectedHeader h (Types.Base64Octets mac)
    encodedProtectedHeader = Just "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    alg = JWA.JWS.HS256
    h = newJWSHeader (Protected, alg)
        & jwsHeaderTyp .~ Just (HeaderParam Protected "JWT")
    mac = foldr BS.cons BS.empty macOctets
    macOctets =
      [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
      187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
      132, 141, 121]
    jwk = JWK (OctKeyMaterial octKeyMaterial) z z z z z z z z where z = Nothing
    octKeyMaterial = OctKeyParameters Oct $ Types.Base64Octets $
      foldr BS.cons BS.empty
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]


appendixA2Spec :: Spec
appendixA2Spec = describe "JWS A.2. Example JWS using RSASSA-PKCS-v1_5 SHA-256" $ do
  it "computes the signature correctly" $
    fst (withDRG drg $ runExceptT (sign JWA.JWS.RS256 (jwk ^. jwkMaterial) signingInput'))
      `shouldBe` (Right sig :: Either Error BS.ByteString)

  it "validates the signature correctly" $
    verify JWA.JWS.RS256 (jwk ^. jwkMaterial) signingInput' sig `shouldBe` Right True

  where
    signingInput' = "\
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
      \}" :: JWK
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


appendixA3Spec :: Spec
appendixA3Spec = describe "JWS A.3.  Example JWS using ECDSA P-256 SHA-256" $
  it "validates the signature correctly" $
    verify JWA.JWS.ES256 (jwk ^. jwkMaterial) signingInput' sig `shouldBe` Right True
  where
    signingInput' = "\
      \eyJhbGciOiJFUzI1NiJ9\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    jwk = fromJust $ decode "\
      \{\"kty\":\"EC\",\
      \ \"crv\":\"P-256\",\
      \ \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\
      \ \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\
      \ \"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"\
      \}" :: JWK
    sig = BS.pack
      [14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88,
      7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129,
      154, 195, 22, 158, 166, 101,
      197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
      8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154,
      143, 63, 127, 138, 131, 163, 84, 213]

appendixA5Spec :: Spec
appendixA5Spec = describe "JWS A.5.  Example Plaintext JWS" $ do
  it "encodes the correct JWS" $
    (jws >>= encodeCompact) `shouldBe` (Right exampleJWS :: Either Error L.ByteString)

  it "decodes the correct JWS" $
    decodeCompact exampleJWS `shouldBe` jws

  where
    jws = fst $ withDRG drg $ runExceptT $
      signJWS (JWS examplePayload []) (newJWSHeader (Protected, JWA.JWS.None)) undefined
    exampleJWS = "eyJhbGciOiJub25lIn0\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ\
      \."


appendixA6Spec :: Spec
appendixA6Spec = describe "JWS A.6.  Example JWS Using JWS JSON Serialization" $
  it "decodes the correct JWS" $ do
    eitherDecode exampleJWS `shouldBe` Right jws
    eitherDecode exampleJWS' `shouldBe` Right jws'
    (eitherDecode exampleFlatJWSWithSignatures :: Either String (JWS JWSHeader))
      `shouldSatisfy` is _Left

  where
    jws = JWS examplePayload [sig1, sig2]
    jws' = JWS examplePayload [sig2]
    sig1 = Signature Nothing h1' (Types.Base64Octets mac1)
    h1 = newJWSHeader (Protected, JWA.JWS.RS256)
    h1' = h1 & jwsHeaderKid .~ Just (HeaderParam Unprotected "2010-12-29")
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
    sig2 = Signature Nothing h2' (Types.Base64Octets mac2)
    h2 = newJWSHeader (Protected, JWA.JWS.ES256)
    h2' = h2 & jwsHeaderKid .~ Just (HeaderParam Unprotected "e9bc097a-ce51-4036-9562-d2ade882db0d")
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
    exampleJWS' = "\
      \{\
      \ \"payload\":\
      \  \"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF\
          \tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\",\
      \ \"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\
      \ \"header\":\
      \   {\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\
      \ \"signature\":\
      \  \"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS\
         \lSApmWQxfKTUJqPP3-Kg6NU1Q\"\
      \}"
    exampleFlatJWSWithSignatures = "\
      \{\
      \ \"payload\":\
      \  \"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF\
          \tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\",\
      \ \"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\
      \ \"header\":\
      \   {\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\
      \ \"signature\":\
      \  \"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS\
         \lSApmWQxfKTUJqPP3-Kg6NU1Q\",\
      \ \"signatures\":\"bogus\"\
      \}"
