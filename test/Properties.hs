-- Copyright (C) 2015  Fraser Tweedale
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

{-# LANGUAGE ScopedTypeVariables #-}

module Properties where

import Control.Applicative

import Data.Aeson
import qualified Data.ByteString as B
import Data.Default.Class

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Monadic
import Test.QuickCheck.Instances ()

import Crypto.JOSE.Types
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS

properties = testGroup "Properties"
  [ testProperty "SizedBase64Integer round-trip" $
    \(n :: SizedBase64Integer) -> decode (encode [n]) == Just [n]
  , testProperty "EC gen, sign and verify" prop_ecSignAndVerify
  ]

prop_ecSignAndVerify :: Crv -> B.ByteString -> Property
prop_ecSignAndVerify crv msg = monadicIO $ do
  k :: JWK <- run $ gen (ECGenParam crv)
  let alg = case crv of P_256 -> ES256 ; P_384 -> ES384 ; P_521 -> ES512
  signResult <- run $ signJWS (newJWS msg) (newJWSHeader alg) k
  case signResult of
    Left e -> do
      monitor (counterexample $ "Failed to sign: " ++ show e)
      assert False
    Right jws -> do
      monitor (counterexample "Failed to verify")
      assert (verifyJWS def def k jws)
