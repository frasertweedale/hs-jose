-- Copyright (C) 2015, 2016  Fraser Tweedale
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

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Monadic
import Test.QuickCheck.Instances ()

import Crypto.JOSE.Types
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS

properties = testGroup "Properties"
  [ testProperty "SizedBase64Integer round-trip"
    (prop_roundTrip :: SizedBase64Integer -> Bool)
  , testProperty "JWK round-trip" (prop_roundTrip :: JWK -> Bool)
  , testProperty "ECDSA gen, sign and verify" prop_ecSignAndVerify
  , testProperty "HMAC gen, sign and verify" prop_hmacSignAndVerify
  , testProperty "RSA gen, sign and verify" prop_rsaSignAndVerify
  ]

prop_roundTrip :: (Eq a, ToJSON a, FromJSON a) => a -> Bool
prop_roundTrip a = decode (encode [a]) == Just [a]

debugRoundTrip
  :: (Show a, Arbitrary a, ToJSON a, FromJSON a)
  => (a -> Bool)
  -> Property
debugRoundTrip f = monadicIO $ do
  a :: a <- pick arbitrary
  let encoded = encode [a]
  monitor $ counterexample $
    "JSON: \n" ++ show encoded ++ "\n\nDecoded: \n" ++ show (decode encoded :: Maybe [a])
  assert $ f a

prop_ecSignAndVerify :: Crv -> B.ByteString -> Property
prop_ecSignAndVerify crv msg = monadicIO $ do
  k :: JWK <- run $ genJWK (ECGenParam crv)
  let alg = case crv of P_256 -> ES256 ; P_384 -> ES384 ; P_521 -> ES512
  wp (signJWS (newJWS msg) (newJWSHeader alg) k) (checkSignJWS k)

prop_hmacSignAndVerify :: B.ByteString -> Property
prop_hmacSignAndVerify msg = monadicIO $ do
  (alg, minLen) <-
    pick $ oneof $ pure <$> [(HS256, 32), (HS384, 48), (HS512, 64)]
  keylen <- (+ minLen) <$> pick arbitrarySizedNatural
  k :: JWK <- run $ genJWK (OctGenParam keylen)
  wp (signJWS (newJWS msg) (newJWSHeader alg) k) (checkSignJWS k)

prop_rsaSignAndVerify :: B.ByteString -> Property
prop_rsaSignAndVerify msg = monadicIO $ do
  keylen <- pick $ oneof $ pure . (`div` 8) <$> [2048, 3072, 4096]
  k :: JWK <- run $ genJWK (RSAGenParam keylen)
  alg <- pick $ oneof $ pure <$> [RS256, RS384, RS512, PS256, PS384, PS512]
  wp (signJWS (newJWS msg) (newJWSHeader alg) k) (checkSignJWS k)

checkSignJWS :: (Monad m, Show e) => JWK -> Either e JWS -> PropertyM m ()
checkSignJWS k signResult = case signResult of
  Left e -> do
    monitor (counterexample $ "Failed to sign: " ++ show e)
    assert False
  Right jws -> do
    monitor (counterexample "Failed to verify")
    assert (verifyJWS (return ()) k jws)
