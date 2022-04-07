-- Copyright (C) 2016  Fraser Tweedale
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

module AESKW where

import qualified Data.ByteString as B
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error

import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Test.Tasty
import Test.Tasty.Hedgehog

import Crypto.JOSE.AESKW


aeskwProperties :: TestTree
aeskwProperties = testGroup "AESKW"
  [ testProperty "AESKW round-trip" prop_roundTrip
  ]

prop_roundTrip :: Property
prop_roundTrip = property $ do
  cekLen <- forAll $ (* 8) . (+ 2) <$> Gen.integral (Range.linear 0 16)
  cek <- forAll $ Gen.bytes (Range.singleton cekLen)
  kekLen <- forAll $ Gen.element [16, 24, 32]
  kek <- forAll $ Gen.bytes (Range.singleton kekLen)
  let
    go cipher' = case cipher' of
      CryptoFailed _ -> do
        annotate "cipherInit failed"
        failure
      CryptoPassed cipher -> do
        let
          c = aesKeyWrap cipher cek :: B.ByteString
          cek' = aesKeyUnwrap cipher c
        B.length c === cekLen + 8
        cek' === Just cek
  case kekLen of
    16 -> go (cipherInit kek :: CryptoFailable AES128)
    24 -> go (cipherInit kek :: CryptoFailable AES192)
    32 -> go (cipherInit kek :: CryptoFailable AES256)
    _  -> annotate "the impossible happened" *> failure   -- can't happen
