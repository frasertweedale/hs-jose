-- Copyright (C) 2013  Fraser Tweedale
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

import Data.Aeson
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Test.Hspec

import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types

spec :: Spec
spec = do
  jwkAppendixA1Spec
  jwsAppendixA1Spec

jwsAppendixA1Spec :: Spec
jwsAppendixA1Spec = describe "JWS A.1.1.  JWK" $ do
  -- can't make aeson encode JSON to exact representation used in
  -- IETF doc, be we can go in reverse and then ensure that the
  -- round-trip checks out
  --
  it "decodes the example to the correct value" $
    decode exampleJWK `shouldBe` Just jwk

  it "round-trips correctly" $
    eitherDecode (encode jwk) `shouldBe` Right jwk

  where
    exampleJWK = "\
      \{\"kty\":\"oct\",\
      \ \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\
               \aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"\
      \}"
    jwk = materialJWK (OctKeyMaterial (OctKeyParameters Oct octOctets))
    octOctets = Types.Base64Octets $ foldr B.cons B.empty
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]

jwkAppendixA1Spec :: Spec
jwkAppendixA1Spec = describe "JWK A.1.  Example Public Keys" $
  it "successfully decodes the examples" $
    lr (eitherDecode exampleJWKSet :: Either String JWKSet) `shouldBe` R
    where
    exampleEC = "\
      \    {\"kty\":\"EC\",\
      \     \"crv\":\"P-256\",\
      \     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\
      \     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\
      \     \"use\":\"enc\",\
      \     \"kid\":\"1\"}"
    exampleRSA = "\
      \    {\"kty\":\"RSA\",\
      \     \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx\
      \4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs\
      \tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2\
      \QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\
      \SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb\
      \w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\
      \     \"e\":\"AQAB\",\
      \     \"alg\":\"RS256\",\
      \     \"kid\":\"2011-04-29\"}"
    exampleJWKSet = "{\"keys\": ["
      `L.append` exampleEC `L.append` ","
      `L.append` exampleRSA `L.append` "]}"


data LR = L | R deriving (Eq, Show)

lr :: Either a b -> LR
lr (Left _) = L
lr _ = R
