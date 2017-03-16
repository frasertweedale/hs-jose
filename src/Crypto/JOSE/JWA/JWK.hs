-- Copyright (C) 2013, 2014, 2015, 2016, 2017  Fraser Tweedale
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

{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeFamilies #-}

{-|

Cryptographic Algorithms for Keys.

-}
module Crypto.JOSE.JWA.JWK (
  -- * Type classes
    AsPublicKey(..)

  -- * Parameters for Elliptic Curve Keys
  , Crv(..)
  , ECKeyParameters(..)

  -- * Parameters for RSA Keys
  , RSAPrivateKeyOthElem(..)
  , RSAPrivateKeyOptionalParameters(..)
  , RSAPrivateKeyParameters(..)
  , RSAKeyParameters(RSAKeyParameters)
  , toRSAKeyParameters
  , rsaE
  , rsaN
  , rsaPrivateKeyParameters
  , rsaPublicKey
  , genRSA

  -- * Parameters for Symmetric Keys
  , OctKeyParameters(..)

  -- * Key generation
  , KeyMaterialGenParam(..)
  , KeyMaterial(..)
  , genKeyMaterial

  -- * Signing and verification
  , sign
  , verify

  , module Crypto.Random
  ) where

import Control.Applicative
import Control.Monad (guard)
import Control.Monad.Except (MonadError(throwError))
import Data.Bifunctor
import Data.Maybe
import Data.Monoid ((<>))

import Control.Lens hiding ((.=), elements)
import Crypto.Hash
import Crypto.MAC.HMAC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.PubKey.ECC.Types as ECC
import Crypto.Random
import Data.Aeson
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.HashMap.Strict as M
import Data.List.NonEmpty
import qualified Data.Text as T
import Test.QuickCheck (Arbitrary(..), arbitrarySizedNatural, elements, oneof)

import Crypto.JOSE.Error
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.TH
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types
import Crypto.JOSE.Types.Orphans ()


-- | \"crv\" (Curve) Parameter
--
$(Crypto.JOSE.TH.deriveJOSEType "Crv" ["P-256", "P-384", "P-521"])

instance Arbitrary Crv where
  arbitrary = oneof $ pure <$> [P_256, P_384, P_521]


-- | \"oth\" (Other Primes Info) Parameter
--
data RSAPrivateKeyOthElem = RSAPrivateKeyOthElem {
  rOth :: Types.Base64Integer,
  dOth :: Types.Base64Integer,
  tOth :: Types.Base64Integer
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOthElem where
  parseJSON = withObject "oth" (\o -> RSAPrivateKeyOthElem <$>
    o .: "r" <*>
    o .: "d" <*>
    o .: "t")

instance ToJSON RSAPrivateKeyOthElem where
  toJSON (RSAPrivateKeyOthElem r d t) = object ["r" .= r, "d" .= d, "t" .= t]

instance Arbitrary RSAPrivateKeyOthElem where
  arbitrary = RSAPrivateKeyOthElem <$> arbitrary <*> arbitrary <*> arbitrary


-- | Optional parameters for RSA private keys
--
data RSAPrivateKeyOptionalParameters = RSAPrivateKeyOptionalParameters {
  rsaP :: Types.Base64Integer
  , rsaQ :: Types.Base64Integer
  , rsaDp :: Types.Base64Integer
  , rsaDq :: Types.Base64Integer
  , rsaQi :: Types.Base64Integer
  , rsaOth :: Maybe (NonEmpty RSAPrivateKeyOthElem)
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyOptionalParameters where
  parseJSON = withObject "RSA" (\o -> RSAPrivateKeyOptionalParameters <$>
    o .: "p" <*>
    o .: "q" <*>
    o .: "dp" <*>
    o .: "dq" <*>
    o .: "qi" <*>
    o .:? "oth")

instance ToJSON RSAPrivateKeyOptionalParameters where
  toJSON (RSAPrivateKeyOptionalParameters {..}) = object $ [
    "p" .= rsaP
    , "q" .= rsaQ
    , "dp" .= rsaDp
    , "dq" .= rsaDq
    , "qi" .= rsaQi
    ] ++ maybe [] ((:[]) . ("oth" .=)) rsaOth

instance Arbitrary RSAPrivateKeyOptionalParameters where
  arbitrary = RSAPrivateKeyOptionalParameters
    <$> arbitrary
    <*> arbitrary
    <*> arbitrary
    <*> arbitrary
    <*> arbitrary
    <*> arbitrary


-- | RSA private key parameters
--
data RSAPrivateKeyParameters = RSAPrivateKeyParameters
  { rsaD :: Types.Base64Integer
  , rsaOptionalParameters :: Maybe RSAPrivateKeyOptionalParameters
  }
  deriving (Eq, Show)

instance FromJSON RSAPrivateKeyParameters where
  parseJSON = withObject "RSA private key parameters" $ \o ->
    RSAPrivateKeyParameters
    <$> o .: "d"
    <*> (if any (`M.member` o) ["p", "q", "dp", "dq", "qi", "oth"]
      then Just <$> parseJSON (Object o)
      else pure Nothing)

instance ToJSON RSAPrivateKeyParameters where
  toJSON RSAPrivateKeyParameters {..} = object $
    ("d" .= rsaD) : maybe [] (Types.objectPairs . toJSON) rsaOptionalParameters

instance Arbitrary RSAPrivateKeyParameters where
  arbitrary = RSAPrivateKeyParameters <$> arbitrary <*> arbitrary


-- | Parameters for Elliptic Curve Keys
--
data ECKeyParameters = ECKeyParameters
  { ecCrv :: Crv
  , ecX :: Types.SizedBase64Integer
  , ecY :: Types.SizedBase64Integer
  , ecD :: Maybe Types.SizedBase64Integer
  }
  deriving (Eq, Show)

instance FromJSON ECKeyParameters where
  parseJSON = withObject "EC" $ \o -> do
    o .: "kty" >>= guard . (== ("EC" :: T.Text))
    crv <- o .: "crv"
    ECKeyParameters
      <$> pure crv
      <*> (o .: "x" >>= Types.checkSize (ecCoordBytes crv))
      <*> (o .: "y" >>= Types.checkSize (ecCoordBytes crv))
      <*> (o .:? "d" >>= \case
        Nothing -> return Nothing
        Just v -> Just <$> Types.checkSize (ecDBytes crv) v)

instance ToJSON ECKeyParameters where
  toJSON (ECKeyParameters {..}) = object $
    [ "kty" .= ("EC" :: T.Text)
    , "crv" .= ecCrv
    , "x" .= ecX
    , "y" .= ecY
    ] ++ fmap ("d" .=) (maybeToList ecD)

instance Arbitrary ECKeyParameters where
  arbitrary = do
    crv <- arbitrary
    let w = ecCoordBytes crv
    ECKeyParameters crv
      <$> Types.genSizedBase64IntegerOf w
      <*> Types.genSizedBase64IntegerOf w
      <*> oneof
        [ pure Nothing
        , Just <$> Types.genSizedBase64IntegerOf (ecDBytes crv)
        ]

signEC
  :: (BA.ByteArrayAccess msg, HashAlgorithm h,
      MonadRandom m, MonadError e m, AsError e)
  => h
  -> ECKeyParameters
  -> msg
  -> m B.ByteString
signEC h (ECKeyParameters {..}) m = case ecD of
  Just ecD' -> sigToBS <$> sig where
    w = ecCoordBytes ecCrv
    sig = ECDSA.sign privateKey h m
    sigToBS (ECDSA.Signature r s) =
      Types.sizedIntegerToBS w r <> Types.sizedIntegerToBS w s
    privateKey = ECDSA.PrivateKey (curve ecCrv) (d ecD')
    d (Types.SizedBase64Integer _ n) = n
  Nothing -> throwError (review _KeyMismatch "not an EC private key")

verifyEC
  :: (BA.ByteArrayAccess msg, HashAlgorithm h)
  => h
  -> ECKeyParameters
  -> msg
  -> B.ByteString
  -> Bool
verifyEC h k m s = ECDSA.verify h pubkey sig m
  where
  pubkey = ECDSA.PublicKey (curve $ ecCrv k) (point k)
  sig = uncurry ECDSA.Signature
    $ bimap Types.bsToInteger Types.bsToInteger
    $ B.splitAt (B.length s `div` 2) s

curve :: Crv -> ECC.Curve
curve = ECC.getCurveByName . curveName where
  curveName P_256 = ECC.SEC_p256r1
  curveName P_384 = ECC.SEC_p384r1
  curveName P_521 = ECC.SEC_p521r1

point :: ECKeyParameters -> ECC.Point
point ECKeyParameters {..} = ECC.Point (integer ecX) (integer ecY) where
  integer (Types.SizedBase64Integer _ n) = n

ecCoordBytes :: Integral a => Crv -> a
ecCoordBytes P_256 = 32
ecCoordBytes P_384 = 48
ecCoordBytes P_521 = 66

ecDBytes :: Integral a => Crv -> a
ecDBytes crv = ceiling (logBase 2 (fromIntegral order) / 8 :: Double) where
  order = ECC.ecc_n $ ECC.common_curve $ curve crv


-- | Parameters for RSA Keys
--
data RSAKeyParameters = RSAKeyParameters
  { _rsaN :: Types.SizedBase64Integer
  , _rsaE :: Types.Base64Integer
  , _rsaPrivateKeyParameters :: Maybe RSAPrivateKeyParameters
  }
  deriving (Eq, Show)
makeLenses ''RSAKeyParameters

instance FromJSON RSAKeyParameters where
  parseJSON = withObject "RSA" $ \o -> do
    o .: "kty" >>= guard . (== ("RSA" :: T.Text))
    RSAKeyParameters
      <$> o .: "n"
      <*> o .: "e"
      <*> if M.member "d" o
        then Just <$> parseJSON (Object o)
        else pure Nothing

instance ToJSON RSAKeyParameters where
  toJSON RSAKeyParameters {..} = object $
      ("kty" .= ("RSA" :: T.Text))
    : ("n" .= _rsaN)
    : ("e" .= _rsaE)
    : maybe [] (Types.objectPairs . toJSON) _rsaPrivateKeyParameters

instance Arbitrary RSAKeyParameters where
  arbitrary = RSAKeyParameters
    <$> arbitrary
    <*> arbitrary
    <*> arbitrary

genRSA :: MonadRandom m => Int -> m RSAKeyParameters
genRSA size = toRSAKeyParameters . snd <$> RSA.generate size 65537

toRSAKeyParameters :: RSA.PrivateKey -> RSAKeyParameters
toRSAKeyParameters (RSA.PrivateKey (RSA.PublicKey s n e) d p q dp dq qi) =
  let i = Types.Base64Integer
  in RSAKeyParameters
    ( Types.SizedBase64Integer s n )
    ( i e )
    ( Just (RSAPrivateKeyParameters (i d)
      (Just (RSAPrivateKeyOptionalParameters
        (i p) (i q) (i dp) (i dq) (i qi) Nothing))) )

signPKCS15
  :: (PKCS15.HashAlgorithmASN1 h, MonadRandom m, MonadError e m, AsError e)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> m B.ByteString
signPKCS15 h k m = case rsaPrivateKey k of
  Left e -> throwError (review _Error e)
  Right k' -> PKCS15.signSafer (Just h) k' m
    >>= either (throwError . review _RSAError) pure

verifyPKCS15
  :: PKCS15.HashAlgorithmASN1 h
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Bool
verifyPKCS15 h k = PKCS15.verify (Just h) (rsaPublicKey k)

signPSS
  :: (HashAlgorithm h, MonadRandom m, MonadError e m, AsError e)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> m B.ByteString
signPSS h k m = case rsaPrivateKey k of
  Left e -> throwError (review _Error e)
  Right k' -> PSS.signSafer (PSS.defaultPSSParams h) k' m
    >>= either (throwError . review _RSAError) pure

verifyPSS
  :: (HashAlgorithm h)
  => h
  -> RSAKeyParameters
  -> B.ByteString
  -> B.ByteString
  -> Bool
verifyPSS h k = PSS.verify (PSS.defaultPSSParams h) (rsaPublicKey k)

rsaPrivateKey :: RSAKeyParameters -> Either Error RSA.PrivateKey
rsaPrivateKey (RSAKeyParameters
  (Types.SizedBase64Integer size n)
  (Types.Base64Integer e)
  (Just (RSAPrivateKeyParameters (Types.Base64Integer d) opt)))
  | isJust (opt >>= rsaOth) = Left OtherPrimesNotSupported
  | size < 2048 `div` 8 = Left KeySizeTooSmall
  | otherwise = Right $
    RSA.PrivateKey (RSA.PublicKey size n e) d
      (opt' rsaP) (opt' rsaQ) (opt' rsaDp) (opt' rsaDq) (opt' rsaQi)
    where
      opt' f = fromMaybe 0 (unB64I . f <$> opt)
      unB64I (Types.Base64Integer x) = x

rsaPrivateKey _ = Left $ KeyMismatch "not an RSA private key"

rsaPublicKey :: RSAKeyParameters -> RSA.PublicKey
rsaPublicKey (RSAKeyParameters
  (Types.SizedBase64Integer size n) (Types.Base64Integer e) _)
  = RSA.PublicKey size n e


-- | Symmetric key parameters data.
--
newtype OctKeyParameters = OctKeyParameters
  { octK :: Types.Base64Octets
  }
  deriving (Eq, Show)

instance FromJSON OctKeyParameters where
  parseJSON = withObject "symmetric key" $ \o -> do
    o .: "kty" >>= guard . (== ("oct" :: T.Text))
    OctKeyParameters <$> o .: "k"

instance ToJSON OctKeyParameters where
  toJSON OctKeyParameters {..} = object
    [ "kty" .= ("oct" :: T.Text)
    , "k" .= octK
    ]

instance Arbitrary OctKeyParameters where
  arbitrary = OctKeyParameters <$> arbitrary

signOct
  :: forall h e m. (HashAlgorithm h, MonadError e m, AsError e)
  => h
  -> OctKeyParameters
  -> B.ByteString
  -> m B.ByteString
signOct h (OctKeyParameters (Types.Base64Octets k)) m =
  if B.length k < hashDigestSize h
  then throwError (review _KeySizeTooSmall ())
  else pure $ B.pack $ BA.unpack (hmac k m :: HMAC h)


-- | Key material sum type.
--
data KeyMaterial
  = ECKeyMaterial ECKeyParameters
  | RSAKeyMaterial RSAKeyParameters
  | OctKeyMaterial OctKeyParameters
  deriving (Eq, Show)

showKeyType :: KeyMaterial -> String
showKeyType (ECKeyMaterial (ECKeyParameters { ecCrv = crv })) = "ECDSA (" ++ show crv ++ ")"
showKeyType (RSAKeyMaterial _) = "RSA"
showKeyType (OctKeyMaterial _) = "symmetric"

instance FromJSON KeyMaterial where
  parseJSON = withObject "KeyMaterial" $ \o ->
    ECKeyMaterial      <$> parseJSON (Object o)
    <|> RSAKeyMaterial <$> parseJSON (Object o)
    <|> OctKeyMaterial <$> parseJSON (Object o)

instance ToJSON KeyMaterial where
  toJSON (ECKeyMaterial p)  = object $ Types.objectPairs (toJSON p)
  toJSON (RSAKeyMaterial p) = object $ Types.objectPairs (toJSON p)
  toJSON (OctKeyMaterial p) = object $ Types.objectPairs (toJSON p)

-- | Keygen parameters.
--
data KeyMaterialGenParam
  = ECGenParam Crv
  -- ^ Generate an EC key with specified curve.
  | RSAGenParam Int
  -- ^ Generate an RSA key with specified size in /bytes/.
  | OctGenParam Int
  -- ^ Generate a symmetric key with specified size in /bytes/.
  deriving (Eq, Show)

instance Arbitrary KeyMaterialGenParam where
  arbitrary = oneof
    [ ECGenParam <$> arbitrary
    , RSAGenParam <$> elements ((`div` 8) <$> [2048, 3072, 4096])
    , OctGenParam <$> liftA2 (+) arbitrarySizedNatural (elements [32, 48, 64])
    ]

genKeyMaterial :: MonadRandom m => KeyMaterialGenParam -> m KeyMaterial
genKeyMaterial (ECGenParam crv) = do
  let
    xyValue = Types.SizedBase64Integer (ecCoordBytes crv)
    dValue = Types.SizedBase64Integer (ecDBytes crv)
  (ECDSA.PublicKey _ p, ECDSA.PrivateKey _ d) <- ECC.generate (curve crv)
  case p of
    ECC.Point x y -> return $ ECKeyMaterial $
      ECKeyParameters crv (xyValue x) (xyValue y) (Just (dValue d))
    ECC.PointO -> genKeyMaterial (ECGenParam crv)  -- JWK cannot represent point at infinity; recurse
genKeyMaterial (RSAGenParam size) = RSAKeyMaterial <$> genRSA size
genKeyMaterial (OctGenParam n) =
  OctKeyMaterial . OctKeyParameters . Types.Base64Octets <$> getRandomBytes n

sign
  :: (MonadRandom m, MonadError e m, AsError e)
  => JWA.JWS.Alg
  -> KeyMaterial
  -> B.ByteString
  -> m B.ByteString
sign JWA.JWS.None _ = \_ -> return ""
sign JWA.JWS.ES256 (ECKeyMaterial k@(ECKeyParameters { ecCrv = P_256 })) = signEC SHA256 k
sign JWA.JWS.ES384 (ECKeyMaterial k@(ECKeyParameters { ecCrv = P_384 })) = signEC SHA384 k
sign JWA.JWS.ES512 (ECKeyMaterial k@(ECKeyParameters { ecCrv = P_521 })) = signEC SHA512 k
sign JWA.JWS.RS256 (RSAKeyMaterial k) = signPKCS15 SHA256 k
sign JWA.JWS.RS384 (RSAKeyMaterial k) = signPKCS15 SHA384 k
sign JWA.JWS.RS512 (RSAKeyMaterial k) = signPKCS15 SHA512 k
sign JWA.JWS.PS256 (RSAKeyMaterial k) = signPSS SHA256 k
sign JWA.JWS.PS384 (RSAKeyMaterial k) = signPSS SHA384 k
sign JWA.JWS.PS512 (RSAKeyMaterial k) = signPSS SHA512 k
sign JWA.JWS.HS256 (OctKeyMaterial k) = signOct SHA256 k
sign JWA.JWS.HS384 (OctKeyMaterial k) = signOct SHA384 k
sign JWA.JWS.HS512 (OctKeyMaterial k) = signOct SHA512 k
sign h k = \_ -> throwError (review _AlgorithmMismatch
  (show h <> "cannot be used with " <> showKeyType k <> " key"))

verify
  :: (MonadError e m, AsError e)
  => JWA.JWS.Alg
  -> KeyMaterial
  -> B.ByteString
  -> B.ByteString
  -> m Bool
verify JWA.JWS.None _ = \_ s -> pure $ s == ""
verify JWA.JWS.ES256 (ECKeyMaterial k) = fmap pure . verifyEC SHA256 k
verify JWA.JWS.ES384 (ECKeyMaterial k) = fmap pure . verifyEC SHA384 k
verify JWA.JWS.ES512 (ECKeyMaterial k) = fmap pure . verifyEC SHA512 k
verify JWA.JWS.RS256 (RSAKeyMaterial k) = fmap pure . verifyPKCS15 SHA256 k
verify JWA.JWS.RS384 (RSAKeyMaterial k) = fmap pure . verifyPKCS15 SHA384 k
verify JWA.JWS.RS512 (RSAKeyMaterial k) = fmap pure . verifyPKCS15 SHA512 k
verify JWA.JWS.PS256 (RSAKeyMaterial k) = fmap pure . verifyPSS SHA256 k
verify JWA.JWS.PS384 (RSAKeyMaterial k) = fmap pure . verifyPSS SHA384 k
verify JWA.JWS.PS512 (RSAKeyMaterial k) = fmap pure . verifyPSS SHA512 k
verify JWA.JWS.HS256 (OctKeyMaterial k) = \m s -> BA.constEq s <$> signOct SHA256 k m
verify JWA.JWS.HS384 (OctKeyMaterial k) = \m s -> BA.constEq s <$> signOct SHA384 k m
verify JWA.JWS.HS512 (OctKeyMaterial k) = \m s -> BA.constEq s <$> signOct SHA512 k m
verify h k = \_ _ -> throwError $ review _AlgorithmMismatch
  (show h <> "cannot be used with " <> showKeyType k <> " key")

instance Arbitrary KeyMaterial where
  arbitrary = oneof
    [ ECKeyMaterial <$> arbitrary
    , RSAKeyMaterial <$> arbitrary
    , OctKeyMaterial <$> arbitrary
    ]


class AsPublicKey k where
  asPublicKey :: Getter k (Maybe k)


instance AsPublicKey OctKeyParameters where
  asPublicKey = to (const Nothing)

instance AsPublicKey RSAKeyParameters where
  asPublicKey = to (Just . set rsaPrivateKeyParameters Nothing)

instance AsPublicKey ECKeyParameters where
  asPublicKey = to (\k -> Just k { ecD = Nothing })

instance AsPublicKey KeyMaterial where
  asPublicKey = to (\x -> case x of
    OctKeyMaterial k  -> OctKeyMaterial  <$> view asPublicKey k
    RSAKeyMaterial k  -> RSAKeyMaterial  <$> view asPublicKey k
    ECKeyMaterial k   -> ECKeyMaterial   <$> view asPublicKey k
    )
