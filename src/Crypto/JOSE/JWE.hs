-- Copyright (C) 2015, 2016, 2017  Fraser Tweedale
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

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.JOSE.JWE
  (
    JWEProtectedHeader(..)

  , JWE(..)
  , GeneralJWE
  , CompactJWE
  , FlattenedJWE

  , encryptJWE
  , bestJWEAlg
  , bestJWEEnc
  , decryptJWE

  , AlgWithEncParams
  , AlgWithParams

  , RSA1_5(..)
  , RSA_OAEP(..)
  , RSA_OAEP_256(..)
  , A128KW(..)
  , A192KW(..)
  , A256KW(..)
  , Dir(..)
  , ECDH_ES(..)
  , ECDH_ES_A128KW(..)
  , ECDH_ES_A192KW(..)
  , ECDH_ES_A256KW(..)
  , A128GCMKW(..)
  , A192GCMKW(..)
  , A256GCMKW(..)
  , PBES2_HS256_A128KW(..)
  , PBES2_HS384_A192KW(..)
  , PBES2_HS512_A256KW(..)
  ) where

import Control.Applicative ((<|>))
import Control.Monad (when)
import Data.Either (isRight)
import Data.Foldable (find, toList)
import Data.Functor.Identity (Identity(..))
import Data.List (intersect)
import Data.Maybe (catMaybes, fromMaybe)
import Data.Monoid (First(..))
import Data.Proxy
import Data.Semigroup ((<>))
import Data.Traversable (for)
import Data.Word (Word8)

import Control.Lens
  ( AsEmpty, Cons, _Just, Lens', _2, firstOf, review, traversed, view, set)
import Control.Lens.Cons.Extras (recons)
import Control.Monad.Except (MonadError, runExceptT, throwError)
import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.List.NonEmpty (NonEmpty)

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Data.Padding
import Crypto.Error
import Crypto.Hash
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.MAC.HMAC
import qualified Crypto.PubKey.ECC.DH as ECC
import Crypto.PubKey.MaskGenFunction
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15

import Crypto.JOSE.AESKW
import Crypto.JOSE.Error
import Crypto.JOSE.Header
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types


critInvalidNames :: [T.Text]
critInvalidNames =
  [ "alg" , "enc" , "zip" , "jku" , "jwk" , "kid"
  , "x5u" , "x5c" , "x5t" , "x5t#S256" , "typ" , "cty" , "crit" ]

newtype CritParameters = CritParameters (NonEmpty (T.Text, Value))
  deriving (Eq, Show)

data NoParams = NoParams

instance ToJSON NoParams where
  toJSON _ = Object mempty

instance FromJSON NoParams where
  parseJSON _ = pure NoParams


class KeyManagementAlgorithm a where
  type EncParams a :: *
  type Params a :: *
  key :: a -> T.Text
  wrapCEK
    :: (MonadRandom m, MonadError e m, AsError e, ProtectionIndicator p)
    => Enc
    -> B.ByteString -- shared CEK
    -> a            -- key management algorithm
    -> EncParams a  -- key encryption parameters
    -> m (Maybe B.ByteString, JWERecipient p)
    -- ^ return a recipient-specific CEK if the algorithm is a
    --   single-recipient algorithm, and the recipient data

  -- | Unwrap an encrypted CEK.  Has 'MonadRandom' constraint because
  --   some algorithms need a random blinder for safe decryption.
  unwrapCEK
    :: (MonadRandom m, MonadError e m, AsError e)
    => a
    -> Params a              -- key management alg parameters
    -> Enc                   -- encryption algorithm (needed for ECDH-ES)
    -> Maybe B.ByteString    -- encrypted cek
    -> JWK                   -- decryption key
    -> m B.ByteString

wrapCEK'
  :: (MonadRandom m, MonadError e m, AsError e, ProtectionIndicator p)
  => Enc
  -> B.ByteString -- shared CEK
  -> AlgWithEncParams
  -> m (Maybe B.ByteString, JWERecipient p)
wrapCEK' enc cek (AlgWithEncParams a p) = wrapCEK enc cek a p

unwrapCEK'
  :: (MonadRandom m, MonadError e m, AsError e)
  => Maybe (JWEProtectedHeader p)
  -> JWERecipient a
  -> JWK
  -> m B.ByteString
unwrapCEK' hp (JWERecipient hu cek') k =
  case (hp >>= _jweAlg) <|> (hu >>= _jweAlg') of
    Just (AlgWithParams a p) ->
      case (hp >>= _jweEnc) <|> (hu >>= _jweEnc') of
        Just enc ->
          unwrapCEK a p enc ((\(Types.Base64Octets s) -> s) <$> cek') k
        Nothing -> throwError $ review _AlgorithmNotImplemented ()
    -- TODO better errors
    Nothing -> throwError $ review _AlgorithmNotImplemented ()

data RSA1_5             = RSA1_5
data RSA_OAEP           = RSA_OAEP
data RSA_OAEP_256       = RSA_OAEP_256
data A128KW             = A128KW
data A192KW             = A192KW
data A256KW             = A256KW
data Dir                = Dir
data ECDH_ES            = ECDH_ES
data ECDH_ES_A128KW     = ECDH_ES_A128KW
data ECDH_ES_A192KW     = ECDH_ES_A192KW
data ECDH_ES_A256KW     = ECDH_ES_A256KW
data A128GCMKW          = A128GCMKW
data A192GCMKW          = A192GCMKW
data A256GCMKW          = A256GCMKW
data PBES2_HS256_A128KW = PBES2_HS256_A128KW
data PBES2_HS384_A192KW = PBES2_HS384_A192KW
data PBES2_HS512_A256KW = PBES2_HS512_A256KW


-- | Choose the "most compatible" JWE key management algorithm to
-- use for the given key, based on what algorithms are required or
-- recommended by RFC 7518 or later specifications.
--
-- * For "RSA" keys, RSA-OAEP.
-- * For "EC" keys, ECDH-ES+A256KW (not ECDH-ES, because this causes
--   problems in multiple-recipient scenarios).
-- * For "oct" keys, if the key size is 128, 192, or 256-bits,
--   A128KW, A192KW and A256KW respectively, otherwise
--   PBES2-HS512+A256KW.
--
bestJWEAlg
  :: (MonadError e m, AsError e)
  => JWK
  -> m AlgWithEncParams
bestJWEAlg k = case view jwkMaterial k of
  ECKeyMaterial _ -> pure $ AlgWithEncParams ECDH_ES_A256KW k
  RSAKeyMaterial _ -> pure $ AlgWithEncParams RSA_OAEP k
  OctKeyMaterial (OctKeyParameters (Types.Base64Octets k'))
    | B.length k' == 128 `div` 8 -> pure $ AlgWithEncParams A128KW k
    | B.length k' == 192 `div` 8 -> pure $ AlgWithEncParams A192KW k
    | B.length k' == 256 `div` 8 -> pure $ AlgWithEncParams A256KW k
    | otherwise -> pure $ AlgWithEncParams PBES2_HS512_A256KW k
  OKPKeyMaterial (X25519Key _ _) -> pure undefined --TODO
  OKPKeyMaterial (Ed25519Key _ _) -> throwError (review _KeyMismatch "Cannot encrypt with OKP EdDSA key")

-- | The strongest JWE content encryption algorithm that is
-- required by RFC 7518 or later specifications; currently
-- A256CBC-HS512.
--
bestJWEEnc :: Enc
bestJWEEnc = A256CBC_HS512


instance KeyManagementAlgorithm RSA1_5 where
  type EncParams RSA1_5 = JWK
  type Params RSA1_5 = NoParams
  key _ = "RSA1_5"

  wrapCEK _enc cek a k = case view jwkMaterial k of
    -- TODO ensure key size > 2048
    RSAKeyMaterial k' -> do
      result <- PKCS15.encrypt (rsaPublicKey k') cek
      either
        (throwError . review _RSAError)
        (\c -> pure $
          let hdr = newJWEPerRecipientHeader (AlgWithParams a NoParams)
          in (Nothing, JWERecipient (Just hdr) (Just (Types.Base64Octets c))))
        result
    _ -> throwError $ review _KeyMismatch ("Cannot use non-RSA key with " <> show (key a) <> " algorithm")

  unwrapCEK a _params _enc encCEK' k =
    case encCEK' of
      Nothing -> throwError $ review _KeyMismatch "Missing encrypted CEK"
      Just encCEK -> case view jwkMaterial k of
        RSAKeyMaterial k' -> do
          k'' <- rsaPrivateKey k'
          PKCS15.decryptSafer k'' encCEK
            >>= either (throwError . review _RSAError) pure
        _ -> throwError $ review _KeyMismatch ("Cannot use non-RSA key with " <> show (key a) <> " algorithm")


instance KeyManagementAlgorithm RSA_OAEP where
  type EncParams RSA_OAEP = JWK
  type Params RSA_OAEP = NoParams
  key _ = "RSA-OAEP"
  wrapCEK _enc = wrapCEK_oaep SHA1
  unwrapCEK a _ _ = unwrapCEK_oaep SHA1 a

instance KeyManagementAlgorithm RSA_OAEP_256 where
  type EncParams RSA_OAEP_256 = JWK
  type Params RSA_OAEP_256 = NoParams
  key _ = "RSA-OAEP-256"
  wrapCEK _enc = wrapCEK_oaep SHA256
  unwrapCEK a _ _ = unwrapCEK_oaep SHA256 a

wrapCEK_oaep
  :: ( MonadRandom m, MonadError e m, AsError e
     , KeyManagementAlgorithm a, Params a ~ NoParams, HashAlgorithm hash
     )
  => hash
  -> B.ByteString -- shared CEK
  -> a            -- key management algorithm
  -> JWK  -- key encryption parameters
  -> m (Maybe B.ByteString, JWERecipient p)
wrapCEK_oaep h cek a k = case view jwkMaterial k of
  -- TODO ensure key size > 2048
  RSAKeyMaterial k' -> do
    result <- OAEP.encrypt (OAEP.OAEPParams h (mgf1 h) Nothing) (rsaPublicKey k') cek
    either
      (throwError . review _RSAError)
      (\c -> pure $
        let hdr = newJWEPerRecipientHeader (AlgWithParams a NoParams)
        in (Nothing, JWERecipient (Just hdr) (Just (Types.Base64Octets c))))
      result
  _ -> throwError $ review _KeyMismatch ("Cannot use non-RSA key with " <> show (key a) <> " algorithm")

unwrapCEK_oaep
  :: ( KeyManagementAlgorithm a
     , MonadRandom m, MonadError e m, AsError e
     , HashAlgorithm hash
     )
  => hash
  -> a
  -> Maybe B.ByteString    -- encrypted cek
  -> JWK                   -- decryption key
  -> m B.ByteString
unwrapCEK_oaep h a encCEK' k =
  case encCEK' of
    Nothing -> throwError $ review _KeyMismatch "Missing encrypted CEK"
    Just encCEK -> case view jwkMaterial k of
      RSAKeyMaterial k' -> do
        k'' <- rsaPrivateKey k'
        OAEP.decryptSafer (OAEP.OAEPParams h (mgf1 h) Nothing) k'' encCEK
          >>= either (throwError . review _RSAError) pure
      _ -> throwError $ review _KeyMismatch ("Cannot use non-RSA key with " <> show (key a) <> " algorithm")

instance KeyManagementAlgorithm A128KW where
  type EncParams A128KW = JWK
  type Params A128KW = NoParams
  key _ = "A128KW"
  wrapCEK _enc = wrapCEK_aeskw (Proxy :: Proxy AES128)
  unwrapCEK a _params _enc = unwrapCEK_aeskw (Proxy :: Proxy AES128) a

instance KeyManagementAlgorithm A192KW where
  type EncParams A192KW = JWK
  type Params A192KW = NoParams
  key _ = "A192KW"
  wrapCEK _enc = wrapCEK_aeskw (Proxy :: Proxy AES192)
  unwrapCEK a _params _enc = unwrapCEK_aeskw (Proxy :: Proxy AES192) a

instance KeyManagementAlgorithm A256KW where
  type EncParams A256KW = JWK
  type Params A256KW = NoParams
  key _ = "A256KW"
  wrapCEK _enc = wrapCEK_aeskw (Proxy :: Proxy AES256)
  unwrapCEK a _params _enc = unwrapCEK_aeskw (Proxy :: Proxy AES256) a

wrapCEK_aeskw
  :: ( KeyManagementAlgorithm a
     , Params a ~ NoParams
     , MonadRandom m, MonadError e m, AsError e
     , BlockCipher128 cipher
     )
  => Proxy cipher
  -> B.ByteString -- shared CEK
  -> a            -- key management algorithm
  -> JWK  -- key encryption parameters
  -> m (Maybe B.ByteString, JWERecipient p)
wrapCEK_aeskw cipherProxy cek a k = case view jwkMaterial k of
  OctKeyMaterial (OctKeyParameters (Types.Base64Octets k')) -> do
    let hdr = newJWEPerRecipientHeader (AlgWithParams a NoParams)
    encCEK <- wrapAESKW cipherProxy k' cek
    pure (Nothing, JWERecipient (Just hdr) (Just (Types.Base64Octets encCEK)))
  _ -> throwError $ review _KeyMismatch ("Cannot use asymmetric key with " <> show (key a) <> " algorithm")

unwrapCEK_aeskw
  :: ( KeyManagementAlgorithm a
     , MonadError e m, AsError e
     , BlockCipher128 cipher
     )
  => Proxy cipher
  -> a
  -> Maybe B.ByteString    -- encrypted cek
  -> JWK                   -- decryption key
  -> m B.ByteString
unwrapCEK_aeskw cipherProxy a encCEK' k =
  case encCEK' of
    Nothing -> throwError $ review _KeyMismatch "Missing encrypted CEK"
    Just encCEK -> case view jwkMaterial k of
      OctKeyMaterial (OctKeyParameters (Types.Base64Octets k')) ->
        unwrapAESKW cipherProxy k' encCEK
      _ -> throwError $ review _KeyMismatch ("Cannot use asymmetric key with " <> show (key a) <> " algorithm")

instance KeyManagementAlgorithm Dir where
  type EncParams Dir = JWK
  type Params Dir = NoParams
  key _ = "dir"

  wrapCEK enc _cek a k = case view jwkMaterial k of
    -- ignore the given CEK and produce the key from the JWK
    OctKeyMaterial (OctKeyParameters (Types.Base64Octets k')) -> do
      when (encKeySize enc /= B.length k')
        (throwError $ review _KeySizeInvalid ())
      let h = newJWEPerRecipientHeader (AlgWithParams a NoParams)
      pure (Just k', JWERecipient (Just h) Nothing)
    _ -> throwError $ review _KeyMismatch ("Cannot use asymmetric key with " <> show (key a) <> " algorithm")

  unwrapCEK a _ _ _ k = case view jwkMaterial k of
    OctKeyMaterial (OctKeyParameters (Types.Base64Octets k')) -> pure k'
    _ -> throwError $ review _KeyMismatch ("Cannot use asymmetric key with " <> show (key a) <> " algorithm")

instance KeyManagementAlgorithm ECDH_ES where
  type EncParams ECDH_ES = JWK
  type Params ECDH_ES = ECDHParameters
  key _ = "ECDH-ES"
  wrapCEK enc _cek a k = do
    (cek, h) <- wrapCEK_ecdh_direct (encKeySize enc) (encToBS enc) a k
    pure (Just cek, JWERecipient (Just h) Nothing)
  unwrapCEK a p enc _encCEK =
    unwrapCEK_ecdh_direct a p (encKeySize enc) (encToBS enc)

instance KeyManagementAlgorithm ECDH_ES_A128KW where
  type EncParams ECDH_ES_A128KW = JWK
  type Params ECDH_ES_A128KW = ECDHParameters
  key _ = "ECDH-ES+A128KW"
  wrapCEK _enc = wrapCEK_ecdh_kw (Proxy :: Proxy AES128)
  unwrapCEK = unwrapCEK_ecdh_kw (Proxy :: Proxy AES128)

instance KeyManagementAlgorithm ECDH_ES_A192KW where
  type EncParams ECDH_ES_A192KW = JWK
  type Params ECDH_ES_A192KW = ECDHParameters
  key _ = "ECDH-ES+A192KW"
  wrapCEK _enc = wrapCEK_ecdh_kw (Proxy :: Proxy AES192)
  unwrapCEK = unwrapCEK_ecdh_kw (Proxy :: Proxy AES192)

instance KeyManagementAlgorithm ECDH_ES_A256KW where
  type EncParams ECDH_ES_A256KW = JWK
  type Params ECDH_ES_A256KW = ECDHParameters
  key _ = "ECDH-ES+A256KW"
  wrapCEK _enc = wrapCEK_ecdh_kw (Proxy :: Proxy AES256)
  unwrapCEK = unwrapCEK_ecdh_kw (Proxy :: Proxy AES256)

wrapCEK_ecdh_direct
  :: ( Params a ~ ECDHParameters, KeyManagementAlgorithm a
     , MonadRandom m, MonadError e m, AsError e
     )
  => Int -> B.ByteString -> a -> JWK -> m (B.ByteString, JWEPerRecipientHeader p)
wrapCEK_ecdh_direct size algid a k = case view jwkMaterial k of
  ECKeyMaterial p -> do
    let crv = view ecCrv p
    epk <- genJWK (ECGenParam crv)
    let (ECKeyMaterial epkParams) = view jwkMaterial epk
    d <- ecPrivateKey epkParams
    let
      z = ECC.getShared (curve crv) d (point p)
      cek = concatKDFJose z size algid Nothing Nothing
      Just epk' = view asPublicKey epk
      ecdhParams = ECDHParameters epk' Nothing Nothing
      h = newJWEPerRecipientHeader (AlgWithParams a ecdhParams)
    pure (cek, h)
  _ -> throwError $ review _KeyMismatch ("Cannot use non-EC key with " <> show (key a) <> " algorithm")

wrapCEK_ecdh_kw
  :: ( Params a ~ ECDHParameters, KeyManagementAlgorithm a
     , MonadRandom m, MonadError e m, AsError e
     , BlockCipher128 cipher
     )
  => Proxy cipher -> B.ByteString -> a -> JWK -> m (Maybe B.ByteString, JWERecipient p)
wrapCEK_ecdh_kw cipherProxy cek a k = do
  let algid = T.encodeUtf8 (key a)
  (kek, h) <- wrapCEK_ecdh_direct (kmKeySize cipherProxy) algid a k
  encCEK <- wrapAESKW cipherProxy kek cek
  pure (Nothing, JWERecipient (Just h) (Just (Types.Base64Octets encCEK)))

unwrapCEK_ecdh_direct
  :: (KeyManagementAlgorithm a, AsError e, MonadError e m)
  => a -> ECDHParameters -> Int -> B.ByteString -> JWK -> m B.ByteString
unwrapCEK_ecdh_direct a (ECDHParameters epk apu apv) klen algid k =
  case view jwkMaterial k of
    ECKeyMaterial ecParams -> do
      d <- ecPrivateKey ecParams
      p <- case view jwkMaterial epk of
        ECKeyMaterial epkParams -> pure epkParams
        _ -> throwError $ review _KeyMismatch "epk is not an EC key"
      let
        z = ECC.getShared (curve (view ecCrv p)) d (point p)
        cek = concatKDFJose z klen algid apu apv
      pure cek
    _ -> throwError $ review _KeyMismatch ("Cannot use non-EC key with " <> show (key a) <> " algorithm")

unwrapCEK_ecdh_kw
  :: ( KeyManagementAlgorithm a, BlockCipher128 cipher
     , MonadError e m, AsError e
     )
  => Proxy cipher -> a -> ECDHParameters -> t -> Maybe B.ByteString -> JWK
  -> m B.ByteString
unwrapCEK_ecdh_kw cipherProxy a p _enc encCEK' k =
  case encCEK' of
    Nothing -> throwError $ review _KeyMismatch "Missing encrypted CEK"
    Just encCEK -> do
      let algid = T.encodeUtf8 (key a)
      kek <- unwrapCEK_ecdh_direct a p (kmKeySize cipherProxy) algid k
      unwrapAESKW cipherProxy kek encCEK

encToBS :: Enc -> B.ByteString
encToBS A128CBC_HS256 = "A128CBC-HS256"
encToBS A192CBC_HS384 = "A192CBC-HS384"
encToBS A256CBC_HS512 = "A256CBC-HS512"
encToBS A128GCM = "A128GCM"
encToBS A192GCM = "A192GCM"
encToBS A256GCM = "A256GCM"

concatKDFRep
  :: forall hash ba. (HashAlgorithm hash, BA.ByteArrayAccess ba)
  => hash
  -> Int -- bytes remaining to generate
  -> Int -- counter
  -> ba -- Z
  -> B.ByteString -- hash input sans counter
  -> B.ByteString -- output
concatKDFRep h n i z otherInfo
  | n <= 0    = mempty
  | otherwise =
    let
      ctx = hashInitWith h
      ctx' = hashUpdate ctx (Types.sizedIntegerToBS 4 i)
      ctx'' = hashUpdate ctx' z
      ctx''' = hashUpdate ctx'' otherInfo
      dig = hashFinalize ctx'''
      w = hashDigestSize h
    in
      case compare n w of
        LT -> BA.convert (BA.takeView dig n)
        EQ -> BA.convert dig
        GT -> BA.convert dig <> concatKDFRep h (n - w) (i + 1) z otherInfo

data OtherInfoInput
  = FixedLength B.ByteString         -- use as-is
  | VariableLength Int B.ByteString  -- prefix with n-byte big-endian length

concatKDF
  :: (BA.ByteArrayAccess ba, HashAlgorithm hash)
  => hash
  -> Int -- key data len
  -> ba -- Z (shared secret)
  -> OtherInfoInput -- AlgorithmID
  -> OtherInfoInput -- PartyUInfo
  -> OtherInfoInput -- PartyVInfo
  -> OtherInfoInput -- SuppPubInfo
  -> OtherInfoInput -- SuppPrivInfo
  -> B.ByteString -- output
concatKDF h len z algid u v supPub supPri =
  let
    prep (FixedLength s) = s
    prep (VariableLength w s) = Types.sizedIntegerToBS w (B.length s) <> s
    otherInfo = prep algid <> prep u <> prep v <> prep supPub <> prep supPri
  in
    concatKDFRep h len 1 z otherInfo

-- | Concat KDF as used in JOSE
concatKDFJose
  :: (BA.ByteArrayAccess ba)
  => ba -- Z (shared secret)
  -> Int -- required key data len
  -> B.ByteString -- algorithm id
  -> Maybe Types.Base64Octets -- PartyUInfo
  -> Maybe Types.Base64Octets -- PartyVInfo
  -> B.ByteString -- output
concatKDFJose z len algid apu apv =
  let
    unB64 (Types.Base64Octets s) = s
    uvInfo = maybe mempty unB64
    var = VariableLength 4
  in
    concatKDF SHA256 len z
      (var algid) (var $ uvInfo apu) (var $ uvInfo apv)
      (FixedLength $ Types.sizedIntegerToBS 4 len) (FixedLength mempty)


instance KeyManagementAlgorithm PBES2_HS256_A128KW where
  -- TODO count, saltlen?  currently hardcoded
  type EncParams PBES2_HS256_A128KW = JWK
  type Params PBES2_HS256_A128KW = PBES2Parameters
  key _ = "PBES2-HS256+A128KW"
  wrapCEK _enc = wrapCEK_pbes2 (Proxy :: Proxy AES128) SHA256
  unwrapCEK a p _enc = unwrapCEK_pbes2 (Proxy :: Proxy AES128) SHA256 a p

instance KeyManagementAlgorithm PBES2_HS384_A192KW where
  type EncParams PBES2_HS384_A192KW = JWK
  type Params PBES2_HS384_A192KW = PBES2Parameters
  key _ = "PBES2-HS384+A192KW"
  wrapCEK _enc = wrapCEK_pbes2 (Proxy :: Proxy AES192) SHA384
  unwrapCEK a p _enc= unwrapCEK_pbes2 (Proxy :: Proxy AES192) SHA384 a p

instance KeyManagementAlgorithm PBES2_HS512_A256KW where
  type EncParams PBES2_HS512_A256KW = JWK
  type Params PBES2_HS512_A256KW = PBES2Parameters
  key _ = "PBES2-HS512+A256KW"
  wrapCEK _enc = wrapCEK_pbes2 (Proxy :: Proxy AES256) SHA512
  unwrapCEK a p _enc = unwrapCEK_pbes2 (Proxy :: Proxy AES256) SHA512 a p

wrapCEK_pbes2
  :: ( KeyManagementAlgorithm a
     , Params a ~ PBES2Parameters
     , MonadRandom m, MonadError e m, AsError e
     , BlockCipher128 cipher, HashAlgorithm hash
     )
  => Proxy cipher
  -> hash
  -> B.ByteString -- shared CEK
  -> a            -- key management algorithm
  -> JWK          -- key encryption parameters
  -> m (Maybe B.ByteString, JWERecipient p)
wrapCEK_pbes2 cipherProxy h cek a k = case view jwkMaterial k of
  OctKeyMaterial (OctKeyParameters (Types.Base64Octets k')) -> do
    salt <- getRandomBytes 8
    let
      count = 1000
      kek = pbkdf2 h salt count k' cipherProxy
      awp = AlgWithParams a (PBES2Parameters (Types.Base64Octets salt) count)
      hdr = newJWEPerRecipientHeader awp
    encCEK <- wrapAESKW cipherProxy kek cek
    pure (Nothing, JWERecipient (Just hdr) (Just (Types.Base64Octets encCEK)))
  _ -> throwError $ review _KeyMismatch ("Cannot use asymmetric key with " <> show (key a) <> " algorithm")

unwrapCEK_pbes2
  :: ( KeyManagementAlgorithm a
     , MonadError e m, AsError e
     , BlockCipher128 cipher, HashAlgorithm hash
     )
  => Proxy cipher
  -> hash
  -> a
  -> PBES2Parameters       -- key management alg parameters
  -> Maybe B.ByteString    -- encrypted cek
  -> JWK                   -- decryption key
  -> m B.ByteString
unwrapCEK_pbes2 cipherProxy h a (PBES2Parameters (Types.Base64Octets salt) count) encCEK' k =
  case encCEK' of
    Nothing -> throwError $ review _KeyMismatch "Missing encrypted CEK"
    Just encCEK ->
      case view jwkMaterial k of
        OctKeyMaterial (OctKeyParameters (Types.Base64Octets k')) -> do
          let kek = pbkdf2 h salt count k' cipherProxy
          unwrapAESKW cipherProxy kek encCEK
        _ -> throwError $ review _KeyMismatch ("Cannot use asymmetric key with " <> show (key a) <> " algorithm")


data AlgWithEncParams where
  AlgWithEncParams
    :: (KeyManagementAlgorithm a)
    => a -> EncParams a -> AlgWithEncParams

data AlgWithParams where
  AlgWithParams
    :: (KeyManagementAlgorithm a, ToJSON (Params a))
    => a -> Params a -> AlgWithParams

instance ToJSON AlgWithParams where
  toJSON (AlgWithParams a p) =
    object $ ("alg" .= key a) : Types.objectPairs (toJSON p)

instance FromJSON AlgWithParams where
  parseJSON = withObject "Encryption alg and params" $ \o ->
    case M.lookup "alg" o of
      Nothing -> fail "\"alg\" parameter is required"
      Just "RSA1_5" -> AlgWithParams RSA1_5 <$> parseJSON (Object o)
      Just "RSA-OAEP" -> AlgWithParams RSA_OAEP <$> parseJSON (Object o)
      Just "RSA-OAEP-256" -> AlgWithParams RSA_OAEP_256 <$> parseJSON (Object o)
      Just "A128KW" -> AlgWithParams A128KW <$> parseJSON (Object o)
      Just "A192KW" -> AlgWithParams A192KW <$> parseJSON (Object o)
      Just "A256KW" -> AlgWithParams A256KW <$> parseJSON (Object o)
      Just "dir" -> pure (AlgWithParams Dir NoParams)
      Just "ECDH-ES" -> AlgWithParams ECDH_ES <$> parseJSON (Object o)
      Just "ECDH-ES+A128KW" -> AlgWithParams ECDH_ES_A128KW <$> parseJSON (Object o)
      Just "ECDH-ES+A192KW" -> AlgWithParams ECDH_ES_A192KW <$> parseJSON (Object o)
      Just "ECDH-ES+A256KW" -> AlgWithParams ECDH_ES_A256KW <$> parseJSON (Object o)
      --TODO Just "A128GCMKW" -> AlgWithParams A128GCMKW <$> parseJSON (Object o)
      --TODO Just "A192GCMKW" -> AlgWithParams A192GCMKW <$> parseJSON (Object o)
      --TODO Just "A256GCMKW" -> AlgWithParams A256GCMKW <$> parseJSON (Object o)
      Just "PBES2-HS256+A128KW" -> AlgWithParams PBES2_HS256_A128KW <$> parseJSON (Object o)
      Just "PBES2-HS384+A192KW" -> AlgWithParams PBES2_HS384_A192KW <$> parseJSON (Object o)
      Just "PBES2-HS512+A256KW" -> AlgWithParams PBES2_HS512_A256KW <$> parseJSON (Object o)
      Just _ -> fail "unrecognised algorithm"


data JWEProtectedHeader a = JWEProtectedHeader
  { _jweAlg :: Maybe AlgWithParams
  , _jweEnc :: Maybe Enc
  , _jweZip :: Maybe String  -- protected header only  "DEF" (DEFLATE) defined
  , _jweJku :: Maybe Types.URI
  , _jweJwk :: Maybe JWK
  , _jweKid :: Maybe String
  , _jweX5u :: Maybe Types.URI
  , _jweX5c :: Maybe (NonEmpty Types.Base64X509)
  , _jweX5t :: Maybe Types.Base64SHA1
  , _jweX5tS256 :: Maybe Types.Base64SHA256
  , _jweTyp :: Maybe String  -- ^ Content Type (of object)
  , _jweCty :: Maybe String  -- ^ Content Type (of payload)
  , _jweCrit :: Maybe (NonEmpty T.Text)
  }
  --deriving (Eq, Show)

instance HasParams JWEProtectedHeader where
  parseParamsFor _ Nothing _ = fail "missing protected header"
  parseParamsFor proxy (Just hp) _ = JWEProtectedHeader
    <$> (hp .:? "alg" >>= traverse (\(_ :: Value) -> parseJSON (Object hp)))
    <*> hp .:? "enc"
    <*> hp .:? "zip"
    <*> hp .:? "jku"
    <*> hp .:? "jwk"
    <*> hp .:? "kid"
    <*> hp .:? "x5u"
    <*> hp .:? "x5c"
    <*> hp .:? "x5t"
    <*> hp .:? "x5t#S256"
    <*> hp .:? "typ"
    <*> hp .:? "cty"
    <*> (hp .:? "crit"
      >>= parseCrit critInvalidNames (extensions proxy) hp)
  params (JWEProtectedHeader awp enc zip' jku' jwk' kid' x5u' x5c' x5t' x5tS256' typ' cty' crit') =
    fmap (True,) (Types.objectPairs (toJSON awp))
    <> catMaybes
      [ fmap (\p -> (True, "enc" .= p)) enc
      , fmap (\p -> (True, "zip" .= p)) zip'
      , fmap (\p -> (True, "jku" .= p)) jku'
      , fmap (\p -> (True, "jwk" .= p)) jwk'
      , fmap (\p -> (True, "kid" .= p)) kid'
      , fmap (\p -> (True, "x5u" .= p)) x5u'
      , fmap (\p -> (True, "x5c" .= p)) x5c'
      , fmap (\p -> (True, "x5t" .= p)) x5t'
      , fmap (\p -> (True, "x5tS256" .= p)) x5tS256'
      , fmap (\p -> (True, "typ" .= p)) typ'
      , fmap (\p -> (True, "cty" .= p)) cty'
      , fmap (\p -> (True, "crit" .= p)) crit'
      ]


data JWEPerRecipientHeader a = JWEPerRecipientHeader
  { _jweAlg' :: Maybe AlgWithParams
  , _jweEnc' :: Maybe Enc
  , _jweJku' :: Maybe Types.URI
  , _jweJwk' :: Maybe JWK
  , _jweKid' :: Maybe String
  , _jweX5u' :: Maybe Types.URI
  , _jweX5c' :: Maybe (NonEmpty Types.Base64X509)
  , _jweX5t' :: Maybe Types.Base64SHA1
  , _jweX5tS256' :: Maybe Types.Base64SHA256
  , _jweTyp' :: Maybe String  -- ^ Content Type (of object)
  , _jweCty' :: Maybe String  -- ^ Content Type (of payload)
  }
  --deriving (Eq, Show)

instance HasParams JWEPerRecipientHeader where
  parseParamsFor _ _ Nothing = fail "missing per-recipient header"
  parseParamsFor _ _ (Just hu) = JWEPerRecipientHeader
    <$> (hu .:? "alg" >>= traverse (\(_ :: Value) -> parseJSON (Object hu)))
    <*> hu .:? "enc"
    <*> hu .:? "jku"
    <*> hu .:? "jwk"
    <*> hu .:? "kid"
    <*> hu .:? "x5u"
    <*> hu .:? "x5c"
    <*> hu .:? "x5t"
    <*> hu .:? "x5t#S256"
    <*> hu .:? "typ"
    <*> hu .:? "cty"
  params (JWEPerRecipientHeader awp enc jku' jwk' kid' x5u' x5c' x5t' x5tS256' typ' cty') =
    fmap (False,) (Types.objectPairs (toJSON awp))
    <> catMaybes
      [ fmap (\p -> (False, "enc" .= p)) enc
      , fmap (\p -> (False, "jku" .= p)) jku'
      , fmap (\p -> (False, "jwk" .= p)) jwk'
      , fmap (\p -> (False, "kid" .= p)) kid'
      , fmap (\p -> (False, "x5u" .= p)) x5u'
      , fmap (\p -> (False, "x5c" .= p)) x5c'
      , fmap (\p -> (False, "x5t" .= p)) x5t'
      , fmap (\p -> (False, "x5tS256" .= p)) x5tS256'
      , fmap (\p -> (False, "typ" .= p)) typ'
      , fmap (\p -> (False, "cty" .= p)) cty'
      ]


newJWEPerRecipientHeader :: AlgWithParams -> JWEPerRecipientHeader p
newJWEPerRecipientHeader awp =
  JWEPerRecipientHeader (Just awp) z z z z z z z z z z
  where z = Nothing


newJWEProtectedHeader :: Enc -> JWEProtectedHeader a
newJWEProtectedHeader enc =
  JWEProtectedHeader z (Just enc) z z z z z z z z z z z
  where z = Nothing


data JWERecipient p = JWERecipient
  (Maybe (JWEPerRecipientHeader p))  -- JWE Per-Recipient Unprotected Header
  (Maybe Types.Base64Octets)  -- JWE Encrypted Key

recipientHeader :: Lens' (JWERecipient p) (Maybe (JWEPerRecipientHeader p))
recipientHeader f (JWERecipient h k)
  = fmap (\h' -> JWERecipient h' k) (f h)

instance (ProtectionIndicator p) => ToJSON (JWERecipient p) where
  toJSON (JWERecipient h cek) =
    object $ catMaybes
      [ fmap (("header" .=) . unprotectedParams) h
        -- the HasParams instance produces all params as unprotected.
      , fmap ("encrypted_key" .=) cek
      ]

parseRecipient
  :: (ProtectionIndicator p)
  => Maybe Object -> Maybe Object -> Value -> Parser (JWERecipient p)
parseRecipient hp hu = withObject "JWE Recipient" $ \o -> do
  hr <- o .:? "header"
  let
    collision (Just m1) (Just m2) = M.keys m1 `intersect` M.keys m2
    collision _ _ = []
    collisionKeys = collision hp hu <> collision hp hr <> collision hu hr
  if not . null $ collisionKeys
    then fail ("parameters occur in multiple headers: " <> show collisionKeys)
    else JWERecipient
      <$> traverse (const $ parseParams hp (hu <> hr)) hr
      <*> o .:? "encrypted_key"

-- parseParamsFor :: HasParams b => Proxy b -> Maybe Object -> Maybe Object -> Parser a

-- | JSON Web Encryption data type.  The payload can only be
-- accessed by decrypting the JWS.
--
-- Parameterised by the signature container type, the header
-- 'ProtectionIndicator' type, and the header record type.
--
-- Use 'encode' and 'decode' to convert a JWE to or from JSON.
-- When encoding a @'JWE' []@ with exactly one recipient, the
-- /flattened JWE JSON serialisation/ syntax is used, otherwise
-- the /general JWE JSON serialisation/ is used.
-- When decoding a @'JWE' []@ either serialisation is accepted.
--
-- @'JWE' 'Identity'@ uses the flattened JSON serialisation
-- or the /JWE compact serialisation/ (see 'decodeCompact' and
-- 'encodeCompact').
--
-- Use 'encryptJWE' to create a JWE encrypted to one or more
-- recipients.
--
-- Use 'decryptJWE' to decrypt a JWE and extract the payload
-- and additional authenticated data.
--
data JWE (t :: * -> *) p = JWE
  { _protectedRaw :: T.Text      -- ^ Encoded protected header
  , _jweProtectedHeader :: Maybe (JWEProtectedHeader ())
  , _jweIv :: Types.Base64Octets  -- ^ JWE Initialization Vector
  , _jweAad :: Maybe Types.Base64Octets -- ^ JWE AAD
  , _jweCiphertext :: Types.Base64Octets  -- ^ JWE Ciphertext
  , _jweTag :: Types.Base64Octets  -- ^ JWE Authentication Tag
  , _jweRecipients :: t (JWERecipient p)
  }

-- | A JWE that allows multiple recipients, and cannot use
-- the /compact serialisation/.  Headers may be 'Protected'
-- or 'Unprotected'.
--
type GeneralJWE = JWE [] Protection

-- | A JWE with one recipient, which uses the
-- /flattened serialisation/.  Headers may be 'Protected'
-- or 'Unprotected'.
--
type FlattenedJWE = JWE Identity Protection

-- | A JWE with one signature which only allows protected
-- parameters.  Can use the /flattened serialisation/ or
-- the /compact serialisation/.
--
type CompactJWE = JWE Identity ()

instance (ProtectionIndicator p) => FromJSON (JWE [] p) where
  parseJSON v = withObject "JWE JSON Serialization" (\o -> do
    hpB64 <- o .:? "protected"
    hp <- for hpB64
      (Types.parseB64Url (maybe
          (fail "protected header contains invalid JSON")
          pure . decode . L.fromStrict))
    hu <- o .:? "unprotected"
    JWE (fromMaybe "" hpB64)
      <$> traverse (const $ parseParams hp Nothing) hp
      <*> o .: "iv"
      <*> o .:? "aad"
      <*> o .: "ciphertext"
      <*> o .: "tag"
      <*> (o .: "recipients" >>= traverse (parseRecipient hp hu))
    ) v
    <|> fmap
      (\(JWE hpRaw hp iv aad p tag (Identity r)) ->
         JWE hpRaw hp iv aad p tag [r])
      (parseJSON v)
  -- TODO check that alg and enc are present for all recips

instance (ProtectionIndicator p) => FromJSON (JWE Identity p) where
  parseJSON = withObject "Flattened JWE JSON Serialization" $ \o ->
    if M.member "recipients" o
    then fail "\"recipients\" member MUST NOT be present"
    else do
      hpB64 <- o .:? "protected"
      hp <- for hpB64
        (Types.parseB64Url (maybe
          (fail "protected header contains invalid JSON")
          pure . decode . L.fromStrict))
      hu <- o .:? "unprotected"
      JWE (fromMaybe "" hpB64)
        <$> traverse (const $ parseParams hp Nothing) hp
        <*> o .: "iv"
        <*> o .:? "aad"
        <*> o .: "ciphertext"
        <*> o .: "tag"
        <*> (Identity <$> parseRecipient hp hu (Object o))
  -- TODO check that alg and enc are present for all recips

instance (ProtectionIndicator p) => ToJSON (JWE [] p) where
  toJSON (JWE hpRaw _hp iv aad m' t rs) =
    let
      recipients = case rs of
        [r] -> Types.objectPairs (toJSON r)
        rs' -> ["recipients" .= rs']
    in
      object $
        catMaybes
          [ if hpRaw == "" then Nothing else Just ("protected" .= hpRaw)
          , fmap ("aad" .=) aad
          ]
        <> ("iv" .= iv : "ciphertext" .= m' : "tag" .= t : recipients)

instance (ProtectionIndicator p) => ToJSON (JWE Identity p) where
  toJSON (JWE hpRaw hp iv aad m' t (Identity r)) =
    toJSON (JWE hpRaw hp iv aad m' t [r])


{-

Here I must make some commentary about how we produce a JWE.
Because of the various configurations of protected/unprotected
headers and of generalised/flattened/compact serialisation, it is hard
tricky to write a general routine that does the right thing.

Let's go over each scenario separately, in terms of the the
specification requires:

- compact (JWE Identity ()): ONLY protected headers are supported;
  and there is only one recipient.  The recipient's headers (which
  are protected) are promoted to become the JWE protected header.

- flattened (JWE Identity Protection): unprotected headers are
  supported, but there is only one recipient.  The recipient's
  PROTECTED headers are promoted to become the JWE Protected
  Header, and the recipient's unprotected headers can be either
  promoted to the JWE Unprotected Header, or left as a JWE
  Per-Recipient Unprotected Header.

- general (JWE [] Protection): unprotected headers are
  supported, and there may be more than one recipient.
  In this case, protected headers must be "lifted" from the
  recipients' headers, and "unioned" in such a way that colliding
  protected keys causes failure (I can't yet see a good way to
  avoid this awkward situation) to become the JWE Protected Header.
  For recipients' unprotected headers, values common across all of
  them could be extracted to the JWE Unprotected Header, or they
  can simply be left as JWE Per-Recipient Unprotected Headers
  (which is simpler).


Here's another approach:

- define separate datatypes for the protected header
  and the per-recip header.  They would have mostly the
  same fields, but per-recip header would not have "crit" or
  "zip" which MUST be carried in JWE Protected Header.

- when encrypting a JWE take a JWEProtectedHeader, and for
  each recipient a JWEPerRecipientUnprotectedHeader.
  No protection parameter is required.  Ensure JWEProtectedHeader
  keys are disjoint from JWEPerRecipientUnprotectedHeader (for
  those fields they have in common).

- when decoding a JWE, parse the protected header as is, then
  for each recipient parse the union of the common JWE Unprotected
  Header and the per-recipient unprotected header, ensuring all
  three headers are disjoint.

- when encoding a Compact JWE, the fields of the sole
  per-recipient header are promoted to the Protected Header.

- the structure can therefore represent invalid states, but
  the only way we construct a JWE is via encryptJWE (which
  checks that the keys are disjoint) or when decoding (which
  also checks that the keys are disjoint).  As long as don't
  expose the relevant constructor(s) it should be safe.

-}


encryptJWE
  ::  ( Cons s1 s1 Word8 Word8, Cons s2 s2 Word8 Word8
      , MonadRandom m, MonadError e m, AsError e
      , Traversable t
      )
  => Enc
  -> s1  -- ^ Message plaintext
  -> s2  -- ^ Additional Authenticated Data
  -> t AlgWithEncParams
  -> m (JWE t Protection)
encryptJWE enc m aad recipients = do
  let
    b64 = Types.Base64Octets
    m' = view recons m
    aad' = view recons aad
    aad'' = if B.null aad' then Nothing else Just aad'
    nRecip = length recipients
    hp = newJWEProtectedHeader enc

  cek <- getRandomBytes (encKeySize enc)

  rs <- for recipients (wrapCEK' enc cek)

  cek' <- case foldMap (toList . fst) rs of
    -- all receipients wrapped the shared CEK
    [] -> pure cek

    -- one recipient used a single-recipient algorithm
    -- and there is only one recipient, so that's fine
    [k] | nRecip == 1 -> pure k

    -- there are multiple CEKs in play
    _ -> throwError $ review _AlgorithmNotImplemented () --TODO better error

  let
    (hp', rs') = if nRecip == 1
      -- merge recip header into protected header and remove recip header
      then case firstOf (traversed . _2 . recipientHeader . _Just) rs of
        Just hu ->
          ( mergeHeaders hp hu
          , set (traversed . _2 . recipientHeader) Nothing rs )
        Nothing -> (hp, rs)

      -- leave everything alone
      else (hp, rs)

  let
    hpRaw = view recons (protectedParamsEncoded hp')
    cipherAAD = maybe hpRaw ((hpRaw <>) .  ("." <>)) aad''

  (iv, c, tag) <- encrypt enc cek' cipherAAD m'
  pure $ JWE
    (T.decodeUtf8 hpRaw) (Just hp')
    (b64 iv) (b64 <$> aad'') (b64 c) (b64 tag)
    (snd <$> rs')


mergeHeaders :: JWEProtectedHeader a -> JWEPerRecipientHeader b -> JWEProtectedHeader a
mergeHeaders
  (JWEProtectedHeader _awp' enc' zip' jku' jwk' kid' x5u' x5c' x5t' x5tS256' typ' cty' crit')
  (JWEPerRecipientHeader awp'' _enc'' _jku'' _jwk'' _kid'' _x5u'' _x5c'' _x5t'' _x5tS256'' _typ'' _cty'')
  =
  -- for now we only have to think about awp and enc,
  -- and we know they are distinct in the single-recipient case,
  -- and we know which "side" each comes from
  -- so just use <|> without scruples
  JWEProtectedHeader awp'' enc' zip' jku' jwk' kid' x5u' x5c' x5t' x5tS256' typ' cty' crit'


decryptJWE
  :: forall m e s t p.
      ( MonadRandom m, MonadError e m, AsError e
      --, JWKStore k
      , Cons s s Word8 Word8, AsEmpty s
      , Traversable t
      )
  => JWK
  -> JWE t p
  -> m s
decryptJWE k (JWE hpRaw hp iv aad c t rs) = do
  let
    unB64 (Types.Base64Octets s) = s
    aad' = unB64 <$> aad
    hEncoded = T.encodeUtf8 hpRaw
    cipherAAD = maybe hEncoded ((hEncoded <>) .  ("." <>)) aad'
    f r = runExceptT $ unwrapCEK' hp r k :: m (Either Error B.ByteString)

  enc <- maybe
    -- assume there is at most one "enc" header in the JWE
    -- (this condition is checked on parse and encrypt)
    (throwError $ review _AlgorithmNotImplemented ()) -- TODO better error
    pure
    ( (hp >>= _jweEnc)
      <|> getFirst (foldMap (\(JWERecipient hu _) -> First (hu >>= _jweEnc')) rs))

  cek' <- find isRight <$> traverse f rs
  -- FIXME gen new CEK and substitute, then continue decryption,
  -- so that we do not reveal whether CEK decryption or content
  -- decryption failed
  case cek' of
    Just (Right cek) ->
      view recons
      <$> decrypt enc cek cipherAAD (unB64 iv) (unB64 c) (unB64 t)
    _ ->
      -- failed to decrypt CEK  TODO better error
      throwError $ review _AlgorithmNotImplemented ()


{-
wrap
  :: (MonadRandom m, MonadError e m, AsError e)
  => AlgWithParams
  -> KeyMaterial
  -> B.ByteString  -- ^ message (key to wrap)
  -> m (AlgWithParams, B.ByteString)
wrap (A128GCMKW _) k m = wrapAESGCM A128GCMKW A128GCM k m
wrap (A192GCMKW _) k m = wrapAESGCM A192GCMKW A192GCM k m
wrap (A256GCMKW _) k m = wrapAESGCM A256GCMKW A256GCM k m

wrapAESGCM
  :: (MonadRandom m, MonadError e m, AsError e)
  => (AESGCMParameters -> AlgWithParams)
  -> Enc
  -> KeyMaterial
  -> B.ByteString
  -> m (AlgWithParams, B.ByteString)
wrapAESGCM f enc (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m =
  (\(iv, tag, m') -> (f (AESGCMParameters (Types.Base64Octets iv) (Types.Base64Octets tag)), m'))
  <$> encrypt enc k m ""
wrapAESGCM _ _ _ _ = throwError $ review _AlgorithmMismatch "Cannot use AESGCMKW with non-Oct key"
-}

pbkdf2 :: (Cipher cipher, HashAlgorithm h) => h -> B.ByteString -> Int -> B.ByteString -> Proxy cipher -> B.ByteString
pbkdf2 h salt count k cipherProxy =
  let pbkdf2Params = PBKDF2.Parameters count (kmKeySize cipherProxy)
  in PBKDF2.generate (PBKDF2.prfHMAC h) pbkdf2Params k salt

-- | Get the key size for a key management algorithm
kmKeySize :: forall cipher. Cipher cipher => Proxy cipher -> Int
kmKeySize _ = case cipherKeySize (undefined :: cipher) of
  KeySizeRange n _ -> n
  KeySizeEnum [] -> 0
  KeySizeEnum (n:_) -> n
  KeySizeFixed n -> n

wrapAESKW
  :: forall cipher m e. (BlockCipher128 cipher, MonadError e m, AsError e)
  => Proxy cipher
  -> B.ByteString -- ^ kek
  -> B.ByteString -- ^ cek (to be encrypted)
  -> m B.ByteString -- ^ encrypted cek
wrapAESKW _ kek cek =
  onCryptoFailure
    (throwError . review _CryptoError)
    (\cipher -> pure (aesKeyWrap cipher cek))
    (cipherInit kek :: CryptoFailable cipher)

unwrapAESKW
  :: forall cipher m e. (BlockCipher128 cipher, MonadError e m, AsError e)
  => Proxy cipher
  -> B.ByteString -- ^ kek
  -> B.ByteString -- ^ encrypted cek
  -> m B.ByteString -- ^ cek
unwrapAESKW _ kek cek =
  onCryptoFailure
    (throwError . review _CryptoError)
    (\cipher -> maybe
      (throwError (review _InvalidTag ())) -- TODO better error
      pure
      (aesKeyUnwrap cipher cek)
    )
    (cipherInit kek :: CryptoFailable cipher)

encKeySize :: Enc -> Int
encKeySize A128CBC_HS256 = 32
encKeySize A192CBC_HS384 = 48
encKeySize A256CBC_HS512 = 64
encKeySize A128GCM = 16
encKeySize A192GCM = 24
encKeySize A256GCM = 32

type Encryptor
  = forall m e. (MonadRandom m, MonadError e m, AsError e)
  => B.ByteString -- ^ key
  -> B.ByteString -- ^ additional authenticated data
  -> B.ByteString -- ^ message
  -> m (B.ByteString, B.ByteString, B.ByteString)  -- ^ iv, ciphertext, tag

encrypt :: Enc -> Encryptor
encrypt enc k
  | B.length k /= encKeySize enc = \_ _ -> throwError $ review _KeySizeInvalid ()
  | otherwise = case enc of
    A128CBC_HS256 -> _cbcHmacEnc SHA256 (undefined :: AES128) k
    A192CBC_HS384 -> _cbcHmacEnc SHA384 (undefined :: AES192) k
    A256CBC_HS512 -> _cbcHmacEnc SHA512 (undefined :: AES256) k
    A128GCM       -> _gcmEnc (undefined :: AES128) k
    A192GCM       -> _gcmEnc (undefined :: AES192) k
    A256GCM       -> _gcmEnc (undefined :: AES256) k

_cbcHmacEnc
  :: forall hash cipher. (HashAlgorithm hash, BlockCipher cipher)
  => hash -> cipher -> Encryptor
_cbcHmacEnc _ _ k aad m = do
  let
    kLen = B.length k `div` 2
    (eKey, mKey) = B.splitAt kLen k
    aadLen = B.reverse $ fst $ B.unfoldrN 8 (\x -> Just (fromIntegral x, x `div` 256)) (B.length aad)
  onCryptoFailure
    (throwError . review _CryptoError)
    (\cipher -> do
      iv <- getRandomBytes (blockSize (cipher :: cipher))
      let
        Just iv' = makeIV iv
        c = cbcEncrypt cipher iv' (pad (PKCS7 $ blockSize cipher) m)
        hmacInput = aad <> iv <> c <> aadLen
        tag = B.take kLen $ BA.convert (hmac mKey hmacInput :: HMAC hash)
      pure (iv, c, tag))
    (cipherInit eKey)

_gcmEnc :: forall cipher. (BlockCipher cipher) => cipher -> Encryptor
_gcmEnc _ k aad m = do
  iv <- getRandomBytes 12
  onCryptoFailure
    (throwError . review _CryptoError)
    (pure . (\(tag, c) -> (iv, c, BA.convert tag)))
    ((\aead -> aeadSimpleEncrypt aead aad m 16)
      <$> (cipherInit k >>= \cipher -> aeadInit AEAD_GCM (cipher :: cipher) iv))


type Decryptor
  = forall m e. (MonadError e m, AsError e)
  => B.ByteString -- ^ key
  -> B.ByteString -- ^ additional authenticated data
  -> B.ByteString -- ^ iv
  -> B.ByteString -- ^ ciphertext
  -> B.ByteString -- ^ tag
  -> m B.ByteString  -- ^ plaintext

decrypt :: Enc -> Decryptor
decrypt enc k
  | B.length k /= encKeySize enc = \_ _ _ _ -> throwError $ review _KeySizeInvalid ()
  | otherwise = case enc of
    A128CBC_HS256 -> _cbcHmacDec SHA256 (undefined :: AES128) k
    A192CBC_HS384 -> _cbcHmacDec SHA384 (undefined :: AES192) k
    A256CBC_HS512 -> _cbcHmacDec SHA512 (undefined :: AES256) k
    A128GCM       -> _gcmDec (undefined :: AES128) k
    A192GCM       -> _gcmDec (undefined :: AES192) k
    A256GCM       -> _gcmDec (undefined :: AES256) k

_cbcHmacDec
  :: forall hash cipher. (HashAlgorithm hash, BlockCipher cipher)
  => hash -> cipher -> Decryptor
_cbcHmacDec _ _ k aad iv c tag = do
  let
    kLen = B.length k `div` 2
    (eKey, mKey) = B.splitAt kLen k
    aadLen = B.reverse $ fst $ B.unfoldrN 8 (\x -> Just (fromIntegral x, x `div` 256)) (B.length aad)
    hmacInput = aad <> iv <> c <> aadLen
    mac = BA.convert (hmac mKey hmacInput :: HMAC hash)
  when (BA.dropView tag 0 /= BA.takeView mac kLen)
    (throwError $ review _InvalidTag ())
  onCryptoFailure
    (throwError . review _CryptoError)
    (\cipher ->
      maybe (throwError $ review _InvalidTag () {- TODO better error -}) pure $
        (makeIV iv :: Maybe (IV cipher))
        >>= \iv' -> unpad (PKCS7 $ blockSize cipher) (cbcDecrypt cipher iv' c)
    )
    (cipherInit eKey)

_gcmDec :: forall cipher. (BlockCipher cipher) => cipher -> Decryptor
_gcmDec _ k aad iv c tag =
  onCryptoFailure
    (throwError . review _CryptoError)
    (maybe (throwError (review _InvalidTag ())) pure)
    ((\aead -> aeadSimpleDecrypt aead aad c (AuthTag (BA.convert tag)))
      <$> (cipherInit k >>= \cipher -> aeadInit AEAD_GCM (cipher :: cipher) iv))
