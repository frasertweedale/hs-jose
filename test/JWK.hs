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

module JWK where

import Data.Maybe

import Data.Aeson
import Data.Attoparsec.Number
import qualified Data.ByteString as BS
import qualified Data.HashMap.Strict as M
import Test.Hspec

import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types

spec =
  jwsAppendixA1Spec

jwsAppendixA1Spec = describe "JWS A.1.1.  JWK" $ do
  -- can't make aeson encode JSON to exact representation used in
  -- IETF doc, be we can go in reverse and then ensure that the
  -- round-trip checks out
  --
  it "decodes the example to the correct value" $ do
    decode exampleJWK `shouldBe` Just jwk

  it "round-trips correctly" $
    eitherDecode (encode jwk) `shouldBe` Right jwk

  where
    exampleJWK = "\
      \{\"kty\":\"oct\",\
      \ \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\
               \aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"\
      \}"
    jwk = material (OctKeyMaterial Oct octKeyMaterial)
    octKeyMaterial = Types.Base64Octets $ foldr BS.cons BS.empty
      [3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,
       230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,
       210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,
       192,205,154,245,103,208,128,163]
