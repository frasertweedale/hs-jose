-- Copyright (C) 2013, 2017  Fraser Tweedale
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

module JWK where

import Data.Monoid ((<>))

import Control.Lens (_Right, view)
import Control.Lens.Extras (is)
import Data.Aeson
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Test.Hspec

import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types

spec :: Spec
spec = do
  jwk3Spec
  jwkAppendixA1Spec
  jwkAppendixA2Spec
  jwkAppendixA3Spec
  jwkAppendixBSpec
  jwkAppendixC1Spec
  jwsAppendixA1Spec
  cfrgSpec

jwsAppendixA1Spec :: Spec
jwsAppendixA1Spec = describe "RFC 7515 A.1.1.  JWK" $ do
  -- can't make aeson encode JSON to exact representation used in
  -- IETF doc, be we can go in reverse and then ensure that the
  -- round-trip checks out
  --
  it "decodes the example to the correct value" $
    decode exampleJWK `shouldBe` Just jwk

  it "round-trips correctly" $
    eitherDecode (encode jwk) `shouldBe` Right jwk

  where
    exampleJWK = ""
      <> "{\"kty\":\"oct\","
      <> "\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75"
      <>         "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\""
      <> "}"
    jwk = JWK (OctKeyMaterial octKeyMaterial) z z z z z z z z where z = Nothing
    octKeyMaterial = OctKeyParameters . Types.Base64Octets $
      foldr B.cons B.empty
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]

jwk3Spec :: Spec
jwk3Spec = describe "RFC 7517 §3. Example JWK" $
  it "successfully decodes the examples" $
    (eitherDecode exampleJWK :: Either String JWK) `shouldSatisfy` is _Right
    where
    exampleJWK = ""
      <> "{\"kty\":\"EC\","
      <> " \"crv\":\"P-256\","
      <> " \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
      <> " \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\","
      <> " \"kid\":\"Public key used in JWS spec Appendix A.3 example\""
      <> "}"

jwkAppendixA1Spec :: Spec
jwkAppendixA1Spec = describe "RFC 7517 A.1.  Example Public Keys" $
  it "successfully decodes the examples" $
    (eitherDecode exampleJWKSet :: Either String JWKSet) `shouldSatisfy` is _Right
    where
    exampleEC = ""
      <> "{\"kty\":\"EC\","
      <> " \"crv\":\"P-256\","
      <> " \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
      <> " \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
      <> " \"use\":\"enc\","
      <> " \"kid\":\"1\"}"
    exampleRSA = ""
      <> "{\"kty\":\"RSA\","
      <> " \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"
      <> "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs"
      <> "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2"
      <> "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI"
      <> "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb"
      <> "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
      <> " \"e\":\"AQAB\","
      <> " \"alg\":\"RS256\","
      <> " \"kid\":\"2011-04-29\"}"
    exampleJWKSet = "{\"keys\": ["
      `L.append` exampleEC `L.append` ","
      `L.append` exampleRSA `L.append` "]}"

jwkAppendixA2Spec :: Spec
jwkAppendixA2Spec = describe "RFC 7517 A.2.  Example Private Keys" $
  it "successfully decodes the examples" $
    (eitherDecode exampleJWKSet :: Either String JWKSet) `shouldSatisfy` is _Right
    where
    exampleJWKSet = ""
      <> "{\"keys\":"
      <> "  ["
      <> "    {\"kty\":\"EC\","
      <> "     \"crv\":\"P-256\","
      <> "     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
      <> "     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
      <> "     \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","
      <> "     \"use\":\"enc\","
      <> "     \"kid\":\"1\"},"
      <> ""
      <> "    {\"kty\":\"RSA\","
      <> "     \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
      <> "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
      <> "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
      <> "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS"
      <> "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw"
      <> "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
      <> "     \"e\":\"AQAB\","
      <> "     \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9"
      <> "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij"
      <> "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d"
      <> "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz"
      <> "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz"
      <> "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\","
      <> "     \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV"
      <> "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV"
      <> "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\","
      <> "     \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum"
      <> "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx"
      <> "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\","
      <> "     \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim"
      <> "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu"
      <> "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\","
      <> "     \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU"
      <> "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9"
      <> "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\","
      <> "     \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg"
      <> "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx"
      <> "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\","
      <> "     \"alg\":\"RS256\","
      <> "     \"kid\":\"2011-04-29\"}"
      <> "  ]"
      <> "}"

jwkAppendixA3Spec :: Spec
jwkAppendixA3Spec = describe "RFC 7517 A.3. Example Symmetric Keys" $
  it "successfully decodes the examples" $
    (eitherDecode exampleJWKSet :: Either String JWKSet) `shouldSatisfy` is _Right
    where
    exampleJWKSet = ""
      <> "{\"keys\":"
      <> "  ["
      <> "    {\"kty\":\"oct\","
      <> "     \"alg\":\"A128KW\","
      <> "     \"k\":\"GawgguFyGrWKav7AX4VKUg\"},"
      <> ""
      <> "    {\"kty\":\"oct\","
      <> "     \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75"
      <> "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\","
      <> "     \"kid\":\"HMAC key used in JWS spec Appendix A.1 example\"}"
      <> "  ]"
      <> "}"

jwkAppendixBSpec :: Spec
jwkAppendixBSpec = describe "JWK B.  Example Use of \"x5c\" (X.509 Certificate Chain) Parameter" $
  it "successfully decodes the example" $
    (eitherDecode exampleJWK :: Either String JWK) `shouldSatisfy` is _Right
    where
    exampleJWK = ""
      <> "{\"kty\":\"RSA\","
      <> " \"use\":\"sig\","
      <> " \"kid\":\"1b94c\","
      <> " \"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08"
      <> "PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q"
      <> "u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"
      <> "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH"
      <> "MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv"
      <> "VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\","
      <> " \"e\":\"AQAB\","
      <> " \"x5c\":"
      <> "  [\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB"
      <> "gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD"
      <> "VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1"
      <> "wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg"
      <> "NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV"
      <> "QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w"
      <> "YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH"
      <> "YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66"
      <> "s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6"
      <> "SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn"
      <> "fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq"
      <> "PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk"
      <> "aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA"
      <> "QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL"
      <> "+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1"
      <> "zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL"
      <> "2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo"
      <> "4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq"
      <> "gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]"
      <> "}"

jwkAppendixC1Spec :: Spec
jwkAppendixC1Spec = describe "RFC 7517  C.1. Plaintext RSA Private Key" $
  it "successfully decodes the example" $
    (eitherDecode exampleJWK :: Either String JWK) `shouldSatisfy` is _Right
    where
    exampleJWK = ""
      <> "{"
      <> " \"kty\":\"RSA\","
      <> " \"kid\":\"juliet@capulet.lit\","
      <> " \"use\":\"enc\","
      <> " \"n\":\"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
      <> "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
      <> "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
      <> "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
      <> "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
      <> "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q\","
      <> " \"e\":\"AQAB\","
      <> " \"d\":\"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"
      <> "NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"
      <> "vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"
      <> "ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"
      <> "rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"
      <> "hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ\","
      <> " \"p\":\"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"
      <> "QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"
      <> "UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws\","
      <> " \"q\":\"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I"
      <> "edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK"
      <> "rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s\","
      <> " \"dp\":\"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3"
      <> "tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w"
      <> "Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c\","
      <> " \"dq\":\"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9"
      <> "GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy"
      <> "mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots\","
      <> " \"qi\":\"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq"
      <> "abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o"
      <> "Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8\""
      <> "}"

cfrgSpec :: Spec
cfrgSpec = describe "RFC 8037 test vectors" $ do
  let
    _A1_jwkJson = ""
      <> "{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
      <> "\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\","
      <> "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"
    _A2_jwkJson = ""
      <> "{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
      <> "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"
    _A1_result = eitherDecode _A1_jwkJson :: Either String JWK
    _A2_result = eitherDecode _A2_jwkJson
  describe "A.1. Ed25519 Private Key" $
    it "successfully decodes the example" $ _A1_result `shouldSatisfy` is _Right
  describe "A.2. Ed25519 Public Key" $ do
    it "successfully decodes the example" $ _A2_result `shouldSatisfy` is _Right
    it "corresponds to A.1. private key" $ Right True == do
      sk <- _A1_result
      pk <- _A2_result
      pure $ maybe False (== pk) (view asPublicKey sk)
