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

import Control.Applicative ((<$>), pure)

import qualified Data.ByteString as B
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error

import Test.QuickCheck.Monadic
import Test.Tasty
import Test.Tasty.QuickCheck

import Crypto.JOSE.AESKW


aeskwProperties = testGroup "AESKW"
  [ testProperty "AESKW round-trip" prop_roundTrip
  ]

prop_roundTrip :: Property
prop_roundTrip = monadicIO $ do
  cekLen <- (* 8) . (+ 2) <$> pick arbitrarySizedNatural
  cek <- pick $ B.pack <$> vectorOf cekLen arbitrary
  kekLen <- pick $ oneof $ pure <$> [16, 24, 32]
  kek <- pick $ B.pack <$> vectorOf kekLen arbitrary
  let
    check :: BlockCipher128 cipher => CryptoFailable cipher -> Bool
    check cipher' = case cipher' of
      CryptoFailed _ -> False
      CryptoPassed cipher ->
        let
          c = aesKeyWrap cipher cek :: B.ByteString
          cek' = aesKeyUnwrap cipher c
        in
          B.length c == cekLen + 8 && cek' == Just cek
  case kekLen of
    16 -> assert $ check (cipherInit kek :: CryptoFailable AES128)
    24 -> assert $ check (cipherInit kek :: CryptoFailable AES192)
    32 -> assert $ check (cipherInit kek :: CryptoFailable AES256)
