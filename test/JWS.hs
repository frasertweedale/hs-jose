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
{-# OPTIONS_GHC -fno-warn-orphans #-}

module JWS where

import Data.Maybe
import Data.Monoid ((<>))

import Control.Lens hiding ((.=))
import Control.Lens.Extras (is)
import Control.Lens.Cons.Extras (recons)
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
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.Types as Types

import Orphans


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
  cfrgSpec


-- Extension of JWSHeader to test "crit" behaviour
--
newtype JWSHeader' p = JWSHeader' { unJWSHeader' :: JWSHeader p }
  deriving (Eq, Show)
_JWSHeader' :: Iso' (JWSHeader' p) (JWSHeader p)
_JWSHeader' = iso unJWSHeader' JWSHeader'
instance HasJWSHeader JWSHeader' where
  jwsHeader = _JWSHeader'
instance HasParams JWSHeader' where
  parseParamsFor proxy hp hu = JWSHeader' <$> parseParamsFor proxy hp hu
  params (JWSHeader' h) = params h
  extensions = const ["foo"]

-- More elaborate extension of JWSHeader to test parsing behaviour
--
data ACMEHeader p = ACMEHeader
  { _acmeJwsHeader :: JWSHeader p
  , _acmeNonce :: Types.Base64Octets
  } deriving (Show)
acmeJwsHeader :: Lens' (ACMEHeader p) (JWSHeader p)
acmeJwsHeader f s@ACMEHeader{ _acmeJwsHeader = a} =
  fmap (\a' -> s { _acmeJwsHeader = a'}) (f a)
acmeNonce :: Lens' (ACMEHeader p) Types.Base64Octets
acmeNonce f s@ACMEHeader{ _acmeNonce = a} =
  fmap (\a' -> s { _acmeNonce = a'}) (f a)
instance HasJWSHeader ACMEHeader where
  jwsHeader = acmeJwsHeader
instance HasParams ACMEHeader where
  parseParamsFor proxy hp hu = ACMEHeader
    <$> parseParamsFor proxy hp hu
    <*> headerRequiredProtected "nonce" hp hu
  params h =
    (True, "nonce" .= view acmeNonce h)
    : params (view acmeJwsHeader h)
  extensions = const ["nonce"]


headerSpec :: Spec
headerSpec = describe "JWS Header" $ do
  it "parses signature correctly" $ do
    let
      sigJSON =
        "{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\
        \ \"header\":{\"kid\":\"2010-12-29\"},\
        \ \"signature\":\"\"}"
      h = newJWSHeader (Protected, JWA.JWS.RS256)
        & kid .~ Just (HeaderParam Unprotected "2010-12-29")
      sig = eitherDecode sigJSON
    sig ^? _Right . header `shouldBe` Just h
    sig ^? _Right . signature `shouldBe` Just ("" :: BS.ByteString)

  it "rejects duplicate headers" $
    let
      -- protected header: {"kid":""}
      s = "{\"protected\":\"eyJraWQiOiIifQ\",\"header\":{\"alg\":\"none\",\"kid\":\"\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader))
        `shouldSatisfy` is _Left

  it "rejects reserved crit parameters" $
    let
      -- protected header: {"crit":["kid"],"kid":""}
      s = "{\"protected\":\"eyJjcml0IjpbImtpZCJdLCJraWQiOiIifQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader))
        `shouldSatisfy` is _Left

  it "rejects unknown crit parameters" $
    let
      -- protected header: {"crit":["foo"],"foo":""}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdLCJmb28iOiIifQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader))
        `shouldSatisfy` is _Left

  it "accepts known crit parameter in protected header" $
    let
      -- protected header: {"crit":["foo"],"foo":""}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdLCJmb28iOiIifQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader'))
        `shouldSatisfy` is _Right

  it "accepts known crit parameter in unprotected header" $
    let
      -- protected header: {"crit":["foo"]}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdfQ\",\"header\":{\"alg\":\"none\",\"foo\":\"\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader'))
        `shouldSatisfy` is _Right

  it "rejects known crit parameter that does not appear in JOSE header" $
    let
      -- protected header: {"crit":["foo"]}
      s = "{\"protected\":\"eyJjcml0IjpbImZvbyJdfQ\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader'))
        `shouldSatisfy` is _Left

  it "rejects unprotected crit parameters" $
    let
      s = "{\"header\":{\"alg\":\"none\",\"crit\":[\"foo\"],\"foo\":\"\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader'))
        `shouldSatisfy` is _Left

  it "rejects empty crit parameters" $
    let
      -- protected header: {"crit":[]}
      s = "{\"protected\":\"eyJjcml0IjpbXX0\",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader'))
        `shouldSatisfy` is _Left

  it "parses required protected header when present in protected header" $
    let
      -- protected header: {"crit":["nonce"],"nonce":"bm9uY2U"}
      s = "{\"protected\":\"eyJjcml0IjpbIm5vbmNlIl0sIm5vbmNlIjoiYm05dVkyVSJ9\""
          <>",\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection ACMEHeader))
        `shouldSatisfy` is _Right

  it "rejects required protected header when present in unprotected header" $
    let
      s = "{\"header\":{\"alg\":\"none\"},\"nonce\":\"bm9uY2U\",\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection ACMEHeader))
        `shouldSatisfy` is _Left

  it "accepts unprotected \"alg\" param with 'Protection' protection indicator" $
    let
      s = "{\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature Protection JWSHeader))
        `shouldSatisfy` is _Right

  it "rejects unprotected \"alg\" param with '()' protection indicator" $
    let
      s = "{\"header\":{\"alg\":\"none\"},\"signature\":\"\"}"
    in
      (eitherDecode s :: Either String (Signature () JWSHeader))
        `shouldSatisfy` is _Left


examplePayloadBytes :: BS.ByteString
examplePayloadBytes = "\
  \{\"iss\":\"joe\",\r\n\
  \ \"exp\":1300819380,\r\n\
  \ \"http://example.com/is_root\":true}"

examplePayload :: Types.Base64Octets
examplePayload = Types.Base64Octets examplePayloadBytes


appendixA1Spec :: Spec
appendixA1Spec = describe "RFC 7515 A.1.  Example JWS using HMAC SHA-256" $ do
  -- can't make aeson encode JSON to exact representation used in
  -- IETF doc, be we can go in reverse and then ensure that the
  -- round-trip checks out
  --
  it "decodes the example to the correct value" $ do
    jws ^? _Right . signatures . signature `shouldBe` Just mac
    jws ^? _Right . signatures . header `shouldBe` Just h

  it "serialises the decoded JWS back to the original data" $
    fmap encodeCompact jws `shouldBe` Right compactJWS

  it "computes the HMAC correctly" $
    fst (withDRG drg $
      runExceptT (sign alg (jwk ^. jwkMaterial) (signingInput' ^. recons)))
      `shouldBe` (Right mac :: Either Error BS.ByteString)

  it "validates the JWS correctly" $
    (jws >>= verifyJWS defaultValidationSettings jwk)
    `shouldBe` Right examplePayloadBytes

  where
    signingInput' = "\
      \eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    compactJWS = signingInput' <> ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    jws = decodeCompact compactJWS :: Either Error (CompactJWS JWSHeader)
    alg = JWA.JWS.HS256
    h = newJWSHeader ((), alg)
        & typ .~ Just (HeaderParam () "JWT")
    mac = view recons
      [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
      187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
      132, 141, 121]
    jwk = fromOctets
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]


jwkRSA1024 :: JWK
jwkRSA1024 = fromJust $ decode $
  "{\"qi\":\"qYMpiKTOyFktv0Z3pQbig1RNA1xH35HMtjwISviC_bGo2zvzrYztBC_RzWsw"
  <> "3Nwsc32n65HIdpNbau1UhB3EwQ\","
  <> "\"p\":\"3ovj_M4MMJamOtjhtjswZhhwSYBiK6f2TjIEWiji-XV9SRcoyJsnp5flpeX"
  <> "VTEXS_PgLmjtUi2MLGAvXLlTtyQ\","
  <> "\"n\":\"yy1luWS19u8F-9eAdJ2iwCvuFrjOKuj1YBeNegPZpMJ9mhi8YISQLg-FTFR"
  <> "J68FzMeZM0liJq9mm-tNfPsNFxU7VM_sha2jWuJI32u3W5m7myTb8vNjHAd8acvuIRJ"
  <> "3hoJpJtSc1XBHHHIUK6lXNepHwQMjSCWtTY2wjRMKvYBU\","
  <> "\"q\":\"6bgjSNOcMzZMh64q66kIU68_U6wHwdbSFyLLtwVORsEYPhQUjWEoO7thY9j"
  <> "7m5NLRWgumoPIdDlLhOOnEf_V7Q\","
  <> "\"d\":\"Mordhkv-VCpLs8V9KAVayjFjbfWVG-mNuNTDFfpFNw5GzoGewufXMg4cW8u"
  <> "QA_zAmkYvEBiETuK6_iR8yhErlqMwFA4mdS4Yq0OqOPd9rCalUOoJf8cV1W5scsWXmL"
  <> "-xX_TmnGnIpjYcDJw6Zw0KP7hvHKPTPUriY2Zb--LLhaE\","
  <> "\"dp\":\"EgxgUglX3bzqAE3EiGXmd_E1chCSZZ36kL7nsXQtbDPGFF5ndVV38tST0E"
  <> "-Ca-whv1hSgJCdO6ytoqabLeu_WQ\","
  <> "\"e\":\"AQAB\","
  <> "\"dq\":\"3gLqkY1hvUwBGomZf85LeKLp9uNdYwZa_1swRCSoHJHkI2QTudDm1QbEFo"
  <> "LRTxF12PKEAobYbX7Xe958n550aQ\","
  <> "\"kty\":\"RSA\"}"

appendixA2Spec :: Spec
appendixA2Spec = describe "RFC 7515 A.2. Example JWS using RSASSA-PKCS-v1_5 SHA-256" $ do
  it "computes the signature correctly" $
    fst (withDRG drg $ runExceptT (sign JWA.JWS.RS256 (jwk ^. jwkMaterial) signingInput'))
      `shouldBe` (Right sig :: Either Error BS.ByteString)

  it "validates the signature correctly" $
    verify JWA.JWS.RS256 (jwk ^. jwkMaterial) signingInput' sig
      `shouldBe` (Right True :: Either Error Bool)

  it "prohibits signing with 1024-bit key" $
    fst (withDRG drg (runExceptT $
      signJWS signingInput' (Identity (newJWSHeader ((), JWA.JWS.RS256), jwkRSA1024))))
        `shouldBe` (Left KeySizeTooSmall :: Either Error (CompactJWS JWSHeader))

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
appendixA3Spec = describe "RFC 7515 A.3.  Example JWS using ECDSA P-256 SHA-256" $
  it "validates the signature correctly" $
    verify JWA.JWS.ES256 (jwk ^. jwkMaterial) signingInput' sig
    `shouldBe` (Right True :: Either Error Bool)
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
appendixA5Spec = describe "RFC 7515 A.5.  Example Unsecured JWS" $ do
  it "encodes the correct JWS" $
    fmap encodeCompact jws `shouldBe` Right exampleJWS

  it "decodes the correct JWS" $
    decodeCompact exampleJWS `shouldBe` jws

  where
    jws = fst $ withDRG drg $ runExceptT $
      signJWS examplePayloadBytes (Identity (newJWSHeader ((), JWA.JWS.None), undefined))
      :: Either Error (CompactJWS JWSHeader)
    exampleJWS = "eyJhbGciOiJub25lIn0\
      \.\
      \eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
      \cGxlLmNvbS9pc19yb290Ijp0cnVlfQ\
      \."


appendixA6Spec :: Spec
appendixA6Spec = describe "RFC 7515 A.6.  Example JWS Using General JSON Serialization" $ do
  it "decodes JWS with multiple signatures correctly" $ do
    let jws = eitherDecode exampleJWSTwoSigs :: Either String (GeneralJWS JWSHeader)
    lengthOf (_Right . signatures) jws `shouldBe` 2
    jws ^? _Right . signatures . header `shouldBe` Just h1'
    jws ^? _Right . signatures . signature `shouldBe` Just mac1
    jws ^? _Right . dropping 1 signatures . header `shouldBe` Just h2'
    jws ^? _Right . dropping 1 signatures . signature `shouldBe` Just mac2

  let
    decodeChecks jws = do
      lengthOf (_Right . signatures) jws `shouldBe` 1
      jws ^? _Right . signatures . header `shouldBe` Just h2'
      jws ^? _Right . signatures . signature `shouldBe` Just mac2

  it "decodes single-sig Generalised JWS correctly" $
    decodeChecks (eitherDecode exampleJWSOneSig :: Either String (GeneralJWS JWSHeader))

  it "fails to decode single-sig Generalised JWS to 'JWS Identity'" $
    (eitherDecode exampleJWSOneSig :: Either String (FlattenedJWS JWSHeader))
      `shouldSatisfy` is _Left

  it "decodes flattened JWS to 'JWS []' correctly" $
    decodeChecks (eitherDecode exampleJWSFlat :: Either String (GeneralJWS JWSHeader))

  it "decodes flattened JWS to 'JWS Identity' correctly" $
    decodeChecks (eitherDecode exampleJWSFlat :: Either String (FlattenedJWS JWSHeader))

  it "fails to decode flattened JWS when \"signatures\" key is present" $ do
    (eitherDecode exampleFlatJWSWithSignatures :: Either String (GeneralJWS JWSHeader))
      `shouldSatisfy` is _Left
    (eitherDecode exampleFlatJWSWithSignatures :: Either String (FlattenedJWS JWSHeader))
      `shouldSatisfy` is _Left

  where
    h1 = newJWSHeader (Protected, JWA.JWS.RS256)
    h1' = h1 & kid .~ Just (HeaderParam Unprotected "2010-12-29")
    mac1 = view recons
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
      251, 71] :: BS.ByteString
    h2 = newJWSHeader (Protected, JWA.JWS.ES256)
    h2' = h2 & kid .~ Just (HeaderParam Unprotected "e9bc097a-ce51-4036-9562-d2ade882db0d")
    mac2 = B64U.decodeLenient
      "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA\
      \pmWQxfKTUJqPP3-Kg6NU1Q"

    exampleJWSTwoSigs = "\
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
    exampleJWSOneSig = "\
      \{\"payload\":\
      \  \"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF\
          \tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\",\
      \ \"signatures\":[\
      \   {\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\
      \    \"header\":\
      \     {\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\
      \    \"signature\":\
      \     \"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS\
            \lSApmWQxfKTUJqPP3-Kg6NU1Q\"}]\
      \}"
    exampleJWSFlat = "\
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

cfrgSpec :: Spec
cfrgSpec = describe "RFC 8037 signature/validation test vectors" $ do
  let
    jwk = fromJust $ decode "\
      \{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\
      \\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\
      \\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"
    sigOctets =
      [0x86,0x0c,0x98,0xd2,0x29,0x7f,0x30,0x60,0xa3,0x3f,0x42,0x73,0x96,0x72,0xd6,0x1b
      ,0x53,0xcf,0x3a,0xde,0xfe,0xd3,0xd3,0xc6,0x72,0xf3,0x20,0xdc,0x02,0x1b,0x41,0x1e
      ,0x9d,0x59,0xb8,0x62,0x8d,0xc3,0x51,0xe2,0x48,0xb8,0x8b,0x29,0x46,0x8e,0x0e,0x41
      ,0x85,0x5b,0x0f,0xb7,0xd8,0x3b,0xb1,0x5b,0xe9,0x02,0xbf,0xcc,0xb8,0xcd,0x0a,0x02]
    sig = BS.pack sigOctets
    signingInput = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
  it "computes the correct signature" $
    fst (withDRG drg $ runExceptT (sign JWA.JWS.EdDSA (view jwkMaterial jwk) signingInput))
      `shouldBe` (Right sig :: Either Error BS.ByteString)
  it "validates signatures correctly" $
    verify JWA.JWS.EdDSA (view jwkMaterial jwk) signingInput sig
      `shouldBe` (Right True :: Either Error Bool)
