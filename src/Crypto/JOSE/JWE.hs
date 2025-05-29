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

{-# LANGUAGE OverloadedStrings #-}

module Crypto.JOSE.JWE
  (
    JWEHeader(..)

  , JWE(..)
  ) where

import Control.Applicative ((<|>))
import Data.Bifunctor (bimap)
import Data.Maybe (catMaybes, fromMaybe)

import Control.Lens (view, views)
import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.Text as T
import Data.List.NonEmpty (NonEmpty)

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Data.Padding
import Crypto.Error
import Crypto.Hash
import Crypto.MAC.HMAC
import Crypto.PubKey.MaskGenFunction
import qualified Crypto.PubKey.RSA.OAEP as OAEP

import Crypto.JOSE.AESKW
import Crypto.JOSE.Error
import Crypto.JOSE.Header
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWK
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

newJWEHeader :: (ProtectionSupport p) => AlgWithParams -> Enc -> JWEHeader p
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


data JWERecipient a p = JWERecipient
  { _jweHeader :: a p
  , _jweEncryptedKey :: Maybe Types.Base64Octets  -- ^ JWE Encrypted Key
  }

instance FromJSON (JWERecipient a p) where
  parseJSON = withObject "JWE Recipient" $ \o -> JWERecipient
    <$> undefined -- o .:? "header"
    <*> o .:? "encrypted_key"

parseRecipient
  :: (HasParams a, ProtectionSupport p)
  => Maybe Object -> Maybe Object -> Value -> Parser (JWERecipient a p)
parseRecipient hp hu = withObject "JWE Recipient" $ \o -> do
  hr <- o .:? "header"
  JWERecipient
    <$> parseParams hp (hu <> hr)  -- TODO fail on key collision in (hr <> hu)
    <*> o .:? "encrypted_key"

-- parseParamsFor :: HasParams b => Proxy b -> Maybe Object -> Maybe Object -> Parser a

data JWE a p = JWE
  { _protectedRaw :: Maybe T.Text       -- ^ Encoded protected header, if available
  , _jweIv :: Maybe Types.Base64Octets  -- ^ JWE Initialization Vector
  , _jweAad :: Maybe Types.Base64Octets -- ^ JWE AAD
  , _jweCiphertext :: Types.Base64Octets  -- ^ JWE Ciphertext
  , _jweTag :: Maybe Types.Base64Octets  -- ^ JWE Authentication Tag
  , _jweRecipients :: [JWERecipient a p]
  }

instance (HasParams a, ProtectionSupport p) => FromJSON (JWE a p) where
  parseJSON = withObject "JWE JSON Serialization" $ \o -> do
    hpB64 <- o .:? "protected"
    hp <- maybe
      (pure Nothing)
      (withText "base64url-encoded header params"
        (Types.parseB64Url (maybe
          (fail "protected header contains invalid JSON")
          pure . decode . L.fromStrict)))
      hpB64
    hu <- o .:? "unprotected"
    JWE
      <$> (Just <$> (o .: "protected" <|> pure ""))  -- raw protected header
      <*> o .:? "iv"
      <*> o .:? "aad"
      <*> o .: "ciphertext"
      <*> o .:? "tag"
      <*> (o .: "recipients" >>= traverse (parseRecipient hp hu))
  -- TODO flattened serialization


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
    (eKey, mKey) = B.splitAt kLen k
    aadLen = B.reverse $ fst $ B.unfoldrN 8 (\x -> Just (fromIntegral x, x `div` 256)) (B.length aad)
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
