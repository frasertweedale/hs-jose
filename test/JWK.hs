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
import qualified Data.ByteString as BS
import Test.Hspec

import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types

spec :: Spec
spec =
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
    jwk = materialJWK (OctKeyMaterial Oct octKeyMaterial)
    octKeyMaterial = OctKeyParameters $ Types.Base64Octets $ foldr BS.cons BS.empty
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]
