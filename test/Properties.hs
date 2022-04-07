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

module Properties where

import Control.Applicative (liftA2)
import Control.Monad.Except (ExceptT)

import Crypto.Number.Basic (log2)
import Data.Aeson (FromJSON, ToJSON, decode, encode)
import qualified Data.ByteString as B

import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Test.Tasty
import Test.Tasty.Hedgehog

import Crypto.JOSE.Types
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS

properties :: TestTree
properties = testGroup "Properties"
  [ testProperty "SizedBase64Integer round-trip" (prop_roundTrip genSizedBase64Integer)
  --, testProperty "JWK round-trip" (prop_roundTrip :: JWK -> Property)  FIXME
  , testProperty "RSA gen, sign and verify" prop_rsaSignAndVerify
  , testProperty "gen, sign with best alg, verify" prop_bestJWSAlg
  ]

genBigInteger :: Gen Integer
genBigInteger = Gen.integral $ Range.exponential 0 (2 ^ (4096 :: Integer))

genBase64Integer :: Gen Base64Integer
genBase64Integer = Base64Integer <$> genBigInteger

genSizedBase64Integer :: Gen SizedBase64Integer
genSizedBase64Integer = do
  x <- genBigInteger
  l <- Gen.element [0, 1, 2]  -- number of leading zero-bytes
  pure $ SizedBase64Integer ((log2 x `div` 8) + 1 + l) x


prop_roundTrip :: (Eq a, Show a, ToJSON a, FromJSON a) => Gen a -> Property
prop_roundTrip gen = property $
  forAll gen >>= \a -> decode (encode [a]) === Just [a]

prop_rsaSignAndVerify :: Property
prop_rsaSignAndVerify = property $ do
  msg <- forAll $ Gen.bytes (Range.linear 0 100)
  keylen <- forAll $ Gen.element ((`div` 8) <$> [2048, 3072, 4096])
  k <- evalIO $ genJWK (RSAGenParam keylen)
  alg_ <- forAll $ Gen.element [RS256, RS384, RS512, PS256, PS384, PS512]
  collect alg_
  msg' <- evalExceptT
    ( signJWS msg [(newJWSHeader (Protected, alg_), k)]
      >>= verifyJWS defaultValidationSettings k
      :: ExceptT Error (PropertyT IO) B.ByteString
    )
  msg' === msg


genCrv :: Gen Crv
genCrv = Gen.element [P_256, P_384, P_521]

genOKPCrv :: Gen OKPCrv
genOKPCrv = Gen.element [Ed25519, X25519]

genKeyMaterialGenParam :: Gen KeyMaterialGenParam
genKeyMaterialGenParam = Gen.choice
  [ ECGenParam <$> genCrv
  , RSAGenParam <$> Gen.element ((`div` 8) <$> [2048, 3072, 4096])
  , OctGenParam <$> liftA2 (+) (Gen.integral (Range.exponential 0 64)) (Gen.element [32, 48, 64])
  , OKPGenParam <$> genOKPCrv
  ]

prop_bestJWSAlg :: Property
prop_bestJWSAlg = property $ do
  msg <- forAll $ Gen.bytes (Range.linear 0 100)

  genParam <- forAll $ genKeyMaterialGenParam
  k <- evalIO $ genJWK genParam

  case bestJWSAlg k of
    Left (KeyMismatch _) -> discard   -- skip non-signing keys
    Left _ -> assert False
    Right alg_ -> do
      collect alg_
      msg' <- evalExceptT
        ( signJWS msg [(newJWSHeader (Protected, alg_), k)]
          >>= verifyJWS defaultValidationSettings k
          :: ExceptT Error (PropertyT IO) B.ByteString
        )
      msg' === msg
