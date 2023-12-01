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

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

module Crypto.JOSE.JWE
  (
    JWEHeader(..)

  , JWE(..)
  , GeneralJWE
  , FlattenedJWE
  , CompactJWE

  , decryptJWE
  , decryptJWE2JWS
  ) where

import Control.Applicative ((<|>))
import Control.Monad (when)
import Data.Bifunctor (bimap, first)
import Data.Maybe (catMaybes, fromMaybe)
import Data.Monoid ((<>))

import Control.Lens hiding ((.=))
import Control.Lens.Cons.Extras (recons)
import Control.Monad.Error.Lens (throwing)
import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.List.NonEmpty (NonEmpty)
import Data.Proxy

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Data.Padding
import Crypto.Error
import Crypto.Hash
import Crypto.MAC.HMAC
import Crypto.PubKey.MaskGenFunction
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.PubKey.RSA.OAEP as OAEP

import Crypto.JOSE.AESKW
import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import Crypto.JOSE.Header
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS (CompactJWS, JWSHeader)
import qualified Crypto.JOSE.Types as Types
import Crypto.JOSE.Types.URI
import qualified Crypto.JOSE.Types.Internal as Types


critInvalidNames :: [T.Text]
critInvalidNames =
  [ "alg" , "enc" , "zip" , "jku" , "jwk" , "kid"
  , "x5u" , "x5c" , "x5t" , "x5t#S256" , "typ" , "cty" , "crit" ]

newtype CritParameters = CritParameters (NonEmpty (T.Text, Value))
  deriving (Eq, Show)


data JWEHeader p = JWEHeader
  { _jweAlg :: Maybe AlgWithParams
  , _jweEnc :: HeaderParam p Enc
  , _jweZip :: Maybe T.Text  -- protected header only  "DEF" (DEFLATE) defined
  , _jweJku :: Maybe (HeaderParam p Types.URI)
  , _jweJwk :: Maybe (HeaderParam p JWK)
  , _jweKid :: Maybe (HeaderParam p T.Text)
  , _jweX5u :: Maybe (HeaderParam p Types.URI)
  , _jweX5c :: Maybe (HeaderParam p (NonEmpty Types.SignedCertificate))
  , _jweX5t :: Maybe (HeaderParam p Types.Base64SHA1)
  , _jweX5tS256 :: Maybe (HeaderParam p Types.Base64SHA256)
  , _jweTyp :: Maybe (HeaderParam p T.Text)  -- ^ Content Type (of object)
  , _jweCty :: Maybe (HeaderParam p T.Text)  -- ^ Content Type (of payload)
  , _jweCrit :: Maybe (NonEmpty T.Text)
  }
  deriving (Eq, Show)

newJWEHeader :: ProtectionIndicator p => AlgWithParams -> Enc -> JWEHeader p
newJWEHeader alg enc =
  JWEHeader (Just alg) (HeaderParam getProtected enc) z z z z z z z z z z z
  where z = Nothing

instance HasParams JWEHeader where
  parseParamsFor proxy hp hu = JWEHeader
    <$> parseJSON (Object (fromMaybe mempty hp <> fromMaybe mempty hu))
    <*> headerRequired "enc" hp hu
    <*> headerOptionalProtected "zip" hp hu
    <*> headerOptional' uriFromJSON "jku" hp hu
    <*> headerOptional "jwk" hp hu
    <*> headerOptional "kid" hp hu
    <*> headerOptional' uriFromJSON "x5u" hp hu
    <*> (fmap . fmap . fmap . fmap)
          (\(Types.Base64X509 cert) -> cert) (headerOptional "x5c" hp hu)
    <*> headerOptional "x5t" hp hu
    <*> headerOptional "x5t#S256" hp hu
    <*> headerOptional "typ" hp hu
    <*> headerOptional "cty" hp hu
    <*> (headerOptionalProtected "crit" hp hu
      >>= parseCrit critInvalidNames (extensions proxy)
        (fromMaybe mempty hp <> fromMaybe mempty hu))
  params (JWEHeader alg enc zip' jku jwk kid x5u x5c x5t x5tS256 typ cty crit) =
    catMaybes
      [ undefined -- TODO
      , Just (view isProtected enc,      "enc" .= view param enc)
      , fmap (\p -> (True, "zip" .= p)) zip'
      , fmap (\p -> (view isProtected p, "jku" .= views param uriToJSON p)) jku
      , fmap (\p -> (view isProtected p, "jwk" .= view param p)) jwk
      , fmap (\p -> (view isProtected p, "kid" .= view param p)) kid
      , fmap (\p -> (view isProtected p, "x5u" .= views param uriToJSON p)) x5u
      , fmap (\p -> (view isProtected p, "x5c" .= fmap Types.Base64X509 (view param p))) x5c
      , fmap (\p -> (view isProtected p, "x5t" .= view param p)) x5t
      , fmap (\p -> (view isProtected p, "x5t#S256" .= view param p)) x5tS256
      , fmap (\p -> (view isProtected p, "typ" .= view param p)) typ
      , fmap (\p -> (view isProtected p, "cty" .= view param p)) cty
      , fmap (\p -> (True, "crit" .= p)) crit
      ]


data JWERecipient p a = JWERecipient
  { _jweHeader :: a p -- ^ Aggregate header from shared protected,
                      -- shared unprotected and per-recipient
                      -- unprotected headers
  , _jweEncryptedKey :: Maybe Types.Base64Octets  -- ^ JWE Encrypted Key
  }

parseRecipient
  :: (HasParams a, ProtectionIndicator p)
  => Maybe Object -> Maybe Object -> Object -> Parser (JWERecipient p a)
parseRecipient hp hu o = do
  hr <- o .:? "header"
  JWERecipient
    <$> parseParams hp (hu <> hr)  -- TODO fail on key collision in (hr <> hu)
    <*> o .:? "encrypted_key"

-- parseParamsFor :: HasParams b => Proxy b -> Maybe Object -> Maybe Object -> Parser a

data JWE t p a = JWE
  { _protectedRaw :: Maybe T.Text       -- ^ Encoded protected header, if available
  , _jweIv :: Maybe Types.Base64Octets  -- ^ JWE Initialization Vector
  , _jweAad :: Maybe Types.Base64Octets -- ^ JWE AAD
  , _jweCiphertext :: Types.Base64Octets  -- ^ JWE Ciphertext
  , _jweTag :: Maybe Types.Base64Octets  -- ^ JWE Authentication Tag
  , _jweRecipients :: t (JWERecipient p a)
  }

type GeneralJWE = JWE [] Protection

type FlattenedJWE = JWE Identity Protection

type CompactJWE = JWE Identity ()

protectedField :: FromJSON a => Object -> Parser (Maybe a)
protectedField o = do
  hpB64 <- o .:? "protected"
  maybe
    (pure Nothing)
    (withText "base64url-encoded header params"
      (Types.parseB64Url (maybe
        (fail "protected header contains invalid JSON")
        pure . decode . L.fromStrict)))
    hpB64

instance (HasParams a, ProtectionIndicator p) => FromJSON (JWE [] p a) where
  parseJSON = withObject "JWE JSON Serialization" $ \o -> do
    hp <- protectedField o
    hu <- o .:? "unprotected"
    JWE
      <$> (Just <$> (o .: "protected" <|> pure ""))  -- raw protected header
      <*> o .:? "iv"
      <*> o .:? "aad"
      <*> o .: "ciphertext"
      <*> o .:? "tag"
      <*> (o .: "recipients" >>= traverse (parseRecipient hp hu))

instance (HasParams a, ProtectionIndicator p) => FromJSON (JWE Identity p a) where
  parseJSON = withObject "Flattened JWE JSON Serialization" $ \o -> do
    hp <- protectedField o
    hu <- o .:? "unprotected"
    JWE
      <$> (Just <$> (o .: "protected" <|> pure ""))  -- raw protected header
      <*> o .:? "iv"
      <*> o .:? "aad"
      <*> o .: "ciphertext"
      <*> o .:? "tag"
      <*> (Identity <$> parseRecipient hp hu o)

instance HasParams a => FromCompact (JWE Identity () a) where
  fromCompact xs = do
    xs' <- traverse (uncurry t) $ zip [0..] xs
    case xs' of
      [_, _, _, _, _] -> do
        let o = object $ zip [ "protected", "encrypted_key", "iv"
                             , "ciphertext", "tag" ] xs'
        case fromJSON o of
          Error e -> throwing _JSONDecodeError e
          Success a -> pure a
      _ -> throwing (_CompactDecodeError . _CompactInvalidNumberOfParts)
             (InvalidNumberOfParts 5 (fromIntegral (length xs')))
    where
      l = _CompactDecodeError . _CompactInvalidText
      t n = either (throwing l . CompactTextError n) (pure . String)
        . T.decodeUtf8' . view recons

wrap
  :: MonadRandom m
  => AlgWithParams
  -> KeyMaterial
  -> B.ByteString  -- ^ message (key to wrap)
  -> m (Either Error (AlgWithParams, B.ByteString))
wrap alg@RSA_OAEP (RSAKeyMaterial k) m = bimap RSAError (alg,) <$>
  OAEP.encrypt (OAEP.OAEPParams SHA1 (mgf1 SHA1) Nothing) (rsaPublicKey k) m
wrap RSA_OAEP _ _ = return $ Left $ AlgorithmMismatch "Cannot use RSA_OAEP with non-RSA key"
wrap alg@RSA_OAEP_256 (RSAKeyMaterial k) m = bimap RSAError (alg,) <$>
  OAEP.encrypt (OAEP.OAEPParams SHA256 (mgf1 SHA256) Nothing) (rsaPublicKey k) m
wrap RSA_OAEP_256 _ _ = return $ Left $ AlgorithmMismatch "Cannot use RSA_OAEP_256 with non-RSA key"
wrap A128KW (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m
  = return $ (A128KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES128) m
wrap A192KW (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m
  = return $ (A192KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES192) m
wrap A256KW (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m
  = return $ (A256KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES256) m
wrap (A128GCMKW _) k m = wrapAESGCM A128GCMKW A128GCM k m
wrap (A192GCMKW _) k m = wrapAESGCM A192GCMKW A192GCM k m
wrap (A256GCMKW _) k m = wrapAESGCM A256GCMKW A256GCM k m
wrap _ _ _ = return $ Left AlgorithmNotImplemented

wrapAESKW
  :: BlockCipher128 cipher
  => CryptoFailable cipher
  -> B.ByteString -- ^ plaintext key (to be encrypted)
  -> Either Error B.ByteString -- ^ encrypted key
wrapAESKW cipher m = case cipher of
  CryptoFailed e -> Left (CryptoError e)
  CryptoPassed cipher' -> Right (aesKeyWrap cipher' m)

wrapAESGCM
  :: MonadRandom m
  => (AESGCMParameters -> AlgWithParams)
  -> Enc
  -> KeyMaterial
  -> B.ByteString
  -> m (Either Error (AlgWithParams, B.ByteString))
wrapAESGCM f enc (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m =
  fmap (\(iv, tag, m') -> (f (AESGCMParameters (Types.Base64Octets iv) (Types.Base64Octets tag)), m'))
  <$> encrypt enc k m ""
wrapAESGCM _ _ _ _ = return $ Left $ AlgorithmMismatch "Cannot use AESGCMKW with non-Oct key"

encrypt
  :: MonadRandom m
  => Enc
  -> B.ByteString -- ^ key
  -> B.ByteString  -- ^ message
  -> B.ByteString  -- ^ AAD
  -> m (Either Error (B.ByteString, B.ByteString, B.ByteString))
encrypt A128CBC_HS256 k m a = case B.length k of
  32 -> _cbcHmacEnc (undefined :: AES128) SHA256 k m a
  _ -> return $ Left KeySizeTooSmall
encrypt A192CBC_HS384 k m a = case B.length k of
  48 -> _cbcHmacEnc (undefined :: AES192) SHA384 k m a
  _ -> return $ Left KeySizeTooSmall
encrypt A256CBC_HS512 k m a = case B.length k of
  64 -> _cbcHmacEnc (undefined :: AES256) SHA512 k m a
  _ -> return $ Left KeySizeTooSmall
encrypt A128GCM k m a = case B.length k of
  16 -> _gcmEnc (undefined :: AES128) k m a
  _ -> return $ Left KeySizeTooSmall
encrypt A192GCM k m a = case B.length k of
  24 -> _gcmEnc (undefined :: AES192) k m a
  _ -> return $ Left KeySizeTooSmall
encrypt A256GCM k m a = case B.length k of
  32 -> _gcmEnc (undefined :: AES256) k m a
  _ -> return $ Left KeySizeTooSmall

_cbcHmacEnc
  :: forall e h m. (BlockCipher e, HashAlgorithm h, MonadRandom m)
  => e
  -> h
  -> B.ByteString -- ^ key
  -> B.ByteString -- ^ message
  -> B.ByteString -- ^ additional authenticated data
  -> m (Either Error (B.ByteString, B.ByteString, B.ByteString))  -- ^ IV, cipertext and MAC
_cbcHmacEnc _ _ k m aad = do
  let
    kLen = B.length k `div` 2
    (mKey, eKey) = B.splitAt kLen k
    aadLen = B.reverse $ fst $ B.unfoldrN 8 (\x -> Just (fromIntegral x, x `div` 256)) (B.length aad * 8)
  case cipherInit eKey of
    CryptoFailed _ -> return $ Left AlgorithmNotImplemented -- FIXME
    CryptoPassed (e :: e) -> do
      iv <- getRandomBytes 16
      case makeIV iv of
        Nothing -> pure $ Left (CryptoError CryptoError_IvSizeInvalid)
        Just iv' -> do
          let m' = pad (PKCS7 $ blockSize e) m
          let c = cbcEncrypt e iv' m'
          let hmacInput = B.concat [aad, iv, c, aadLen]
          let tag = BA.convert $ BA.takeView (hmac mKey hmacInput :: HMAC h) kLen
          pure $ Right (iv, c, tag)

_gcmEnc
  :: forall e m. (BlockCipher e, MonadRandom m)
  => e
  -> B.ByteString -- ^ key
  -> B.ByteString -- ^ message
  -> B.ByteString -- ^ additional authenticated data
  -> m (Either Error (B.ByteString, B.ByteString, B.ByteString))  -- ^ IV, tag and ciphertext
_gcmEnc _ k m aad = do
  iv <- getRandomBytes 12
  case cipherInit k of
    CryptoFailed _ -> return $ Left AlgorithmNotImplemented -- FIXME
    CryptoPassed (e :: e) -> case aeadInit AEAD_GCM e iv of
      CryptoFailed _ -> return $ Left AlgorithmNotImplemented -- FIXME
      CryptoPassed aead -> do
        let m' = pad (PKCS7 $ blockSize e) m
        let (c, aeadFinal) = aeadEncrypt (aeadAppendHeader aead aad) m'
        let tag = BA.pack $ BA.unpack $ aeadFinalize aeadFinal 16
        return $ Right (iv, tag, c)

-- | Decrypt JWE contents.  It's application specific how to handle
-- partial successes but if all fail it should always be treated as
-- failure.
decryptJWE
  :: Functor t
  => JWK
  -> Maybe RSA.Blinder
  -> JWE t p JWEHeader
  -> t (Either Error B.ByteString)
decryptJWE k blinder jwe = fmap decrypt' $ _jweRecipients jwe
  where
    iv = maybe "" (\(Types.Base64Octets x) -> x) $ _jweIv jwe
    aad = case (_protectedRaw jwe, _jweAad jwe) of
      (Just h, Just (Types.Base64Octets x)) | String a <- Types.encodeB64 x -> h <> "." <> a
      (Just h, _) -> h
      (_, Just (Types.Base64Octets x)) | String a <- Types.encodeB64 x -> a
      _ -> ""
    ciphertext = (\(Types.Base64Octets x) -> x) $ _jweCiphertext jwe
    tag = maybe "" (\(Types.Base64Octets x) -> x) $ _jweTag jwe
    decrypt' :: JWERecipient p JWEHeader -> Either Error B.ByteString
    decrypt' recipient = do
      enc <- case _jweAlg $ _jweHeader recipient of
        Just RSA_OAEP -> do
          let header = _jweHeader recipient
          pure $ view param $ _jweEnc header
        _ -> Left AlgorithmNotImplemented
      cek <- case (k ^. jwkMaterial, _jweAlg $ _jweHeader recipient) of
        (RSAKeyMaterial m, Just RSA_OAEP) -> do
          privateKey <- rsaPrivateKey m
          let oaepParams = (OAEP.OAEPParams SHA1 (mgf1 SHA1) Nothing)
          encryptedKey <-
            maybe
              (Left JWEIntegrityFailed)
              (\(Types.Base64Octets x) -> Right x) $
              _jweEncryptedKey recipient
          -- TODO think about blinder use.
          first RSAError (OAEP.decrypt blinder oaepParams privateKey encryptedKey)
        _ -> Left AlgorithmNotImplemented
      -- Validate and decrypt
      decrypt enc cek aad iv ciphertext tag

decryptJWE2JWS
  :: JWK
  -> Maybe RSA.Blinder
  -> JWE Identity () JWEHeader
  -> Either Error (CompactJWS JWSHeader)
decryptJWE2JWS k blinder jwe = do
  decodeCompact . L.fromStrict =<< runIdentity (decryptJWE k blinder jwe)

decrypt
  :: Enc
  -> B.ByteString -- ^ key
  -> T.Text -- ^ additional authenticated data
  -> B.ByteString -- ^ iv
  -> B.ByteString -- ^ ciphertext
  -> B.ByteString -- ^ tag
  -> Either Error B.ByteString
decrypt A128CBC_HS256 k a i c t = case B.length k of
  32 ->_cbcHmacDec (Proxy :: Proxy AES128) (Proxy :: Proxy SHA256) k a i c t
  _ -> Left KeySizeTooSmall
decrypt A192CBC_HS384 k a i c t = case B.length k of
  48 -> _cbcHmacDec (Proxy :: Proxy AES192) (Proxy :: Proxy SHA384) k a i c t
  _ -> Left KeySizeTooSmall
decrypt A256CBC_HS512 k a i c t = case B.length k of
  64 -> _cbcHmacDec (Proxy :: Proxy AES256) (Proxy :: Proxy SHA512) k a i c t
  _ -> Left KeySizeTooSmall
decrypt _ _ _ _ _ _ = Left AlgorithmNotImplemented

_cbcHmacDec
  :: forall e h. (BlockCipher e, HashAlgorithm h)
  => Proxy e
  -> Proxy h
  -> B.ByteString -- ^ key
  -> T.Text -- ^ additional authenticated data
  -> B.ByteString -- ^ iv
  -> B.ByteString -- ^ ciphertext
  -> B.ByteString -- ^ tag
  -> Either Error B.ByteString -- ^ message
_cbcHmacDec _ _ k aadText iv c tag = do
  let
    aad = T.encodeUtf8 aadText
    kLen = B.length k `div` 2
    (mKey, eKey) = B.splitAt kLen k
    aadLen = B.reverse $ fst $ B.unfoldrN 8 (\x -> Just (fromIntegral x, x `div` 256)) (B.length aad * 8)
  case (cipherInit eKey, makeIV iv) of
    (_, Nothing) -> Left $ CryptoError CryptoError_IvSizeInvalid
    (CryptoPassed (e :: e), Just iv') -> do
      let m' = cbcDecrypt e iv' c
      m <- case unpad (PKCS7 $ blockSize e) m' of
        Nothing -> Left JWEIntegrityFailed
        Just m -> pure m
      let hmacInput = B.concat [aad, iv, c, aadLen]
      let tag' = BA.convert $ BA.takeView (hmac mKey hmacInput :: HMAC h) kLen
      let tag'' :: B.ByteString = BA.convert $ BA.takeView tag kLen
      -- Check the integrity of aad+ciphertext
      when (tag'' /= tag') $ Left JWEIntegrityFailed
      -- aad and e are considered valid
      pure m
    _ -> Left AlgorithmNotImplemented
