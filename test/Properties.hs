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

{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}

module Properties where

import Control.Applicative (liftA2)
import Control.Monad.Except (ExceptT)

import Control.Lens ((&), set, view)
import Crypto.Error (onCryptoFailure)
import Crypto.Number.Basic (log2)
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Curve25519 as Curve25519
import Crypto.Random
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
  [ let n = "SizedBase64Integer round-trip" in testPropertyNamed n n (prop_roundTrip genSizedBase64Integer)
  , let n = "JWK round-trip" in testPropertyNamed n n (prop_roundTrip genJWK')
  , let n = "RSA gen, sign and verify" in testPropertyNamed n n prop_rsaSignAndVerify
  , let n = "gen, sign with best alg, verify" in testPropertyNamed n n prop_bestJWSAlg
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




genRSAPrivateKeyOthElem :: Gen RSAPrivateKeyOthElem
genRSAPrivateKeyOthElem =
  RSAPrivateKeyOthElem <$> genBase64Integer <*> genBase64Integer <*> genBase64Integer

genRSAPrivateKeyOptionalParameters :: Gen RSAPrivateKeyOptionalParameters
genRSAPrivateKeyOptionalParameters =
  RSAPrivateKeyOptionalParameters
    <$> genBase64Integer
    <*> genBase64Integer
    <*> genBase64Integer
    <*> genBase64Integer
    <*> genBase64Integer
    <*> Gen.maybe (Gen.nonEmpty (Range.linear 1 3) genRSAPrivateKeyOthElem)

genRSAPrivateKeyParameters :: Gen RSAPrivateKeyParameters
genRSAPrivateKeyParameters =
  RSAPrivateKeyParameters
    <$> genBase64Integer
    <*> Gen.maybe (genRSAPrivateKeyOptionalParameters)

genRSAKeyParameters :: Gen RSAKeyParameters
genRSAKeyParameters =
  RSAKeyParameters
    <$> genBase64Integer
    <*> genBase64Integer
    <*> Gen.maybe (genRSAPrivateKeyParameters)

genECKeyParameters :: Gen ECKeyParameters
genECKeyParameters = do
    let word64 = Gen.word64 Range.constantBounded
    seed <- (,,,,) <$> word64 <*> word64 <*> word64 <*> word64 <*> word64
    let drg = drgNewTest seed
    crv <- genCrv
    let (k, _) = withDRG drg (genEC crv)
    includePrivate <- Gen.bool
    pure $ if includePrivate
      then k
      else (let Just a = view asPublicKey k in a)

genOctKeyParameters :: Gen OctKeyParameters
genOctKeyParameters = OctKeyParameters . Base64Octets <$> Gen.bytes (Range.linear 16 128)

genOKPKeyParameters :: Gen OKPKeyParameters
genOKPKeyParameters = Gen.choice
  [ Ed25519Key
    <$> keyOfLen 32 Ed25519.publicKey
    <*> Gen.maybe (keyOfLen 32 Ed25519.secretKey)
  , X25519Key
    <$> keyOfLen 32 Curve25519.publicKey
    <*> Gen.maybe (keyOfLen 32 Curve25519.secretKey)
  ]
  where
    bsOfLen n = Gen.bytes (Range.singleton n)
    keyOfLen n con = onCryptoFailure (error . show) id . con <$> bsOfLen n

genKeyMaterial' :: Gen KeyMaterial
genKeyMaterial' = Gen.choice
  [ ECKeyMaterial <$> genECKeyParameters
  , RSAKeyMaterial <$> genRSAKeyParameters
  , OctKeyMaterial <$> genOctKeyParameters
  , OKPKeyMaterial <$> genOKPKeyParameters
  ]

genBase64SHA1 :: Gen Base64SHA1
genBase64SHA1 = Base64SHA1 <$> Gen.bytes (Range.singleton 20)

genBase64SHA256 :: Gen Base64SHA256
genBase64SHA256 = Base64SHA256 <$> Gen.bytes (Range.singleton 32)

genJWK' :: Gen JWK
genJWK' = do
  key <- genKeyMaterial'
  kid_ <- Gen.text (Range.linear 8 16) Gen.hexit
  x5t_ <- genBase64SHA1
  x5tS256_ <- genBase64SHA256
  pure $ fromKeyMaterial key
    & set jwkKid (Just kid_)
    & set jwkX5t (Just x5t_)
    & set jwkX5tS256 (Just x5tS256_)
