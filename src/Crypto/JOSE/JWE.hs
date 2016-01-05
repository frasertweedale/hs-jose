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

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

module Crypto.JOSE.JWE
  (
    JWEHeader(..)

  , JWE(..)
  ) where

import Prelude hiding (mapM)
import Control.Applicative
import Data.Bifunctor (first, bimap)
import Data.Maybe (catMaybes)
import Data.Traversable (mapM)

import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.List.NonEmpty (NonEmpty(..), toList)

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
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types
import Crypto.JOSE.Types.Armour


critInvalidNames :: [T.Text]
critInvalidNames =
  [ "alg" , "enc" , "zip" , "jku" , "jwk" , "kid"
  , "x5u" , "x5c" , "x5t" , "x5t#S256" , "typ" , "cty" , "crit" ]

newtype CritParameters = CritParameters (NonEmpty (T.Text, Value))
  deriving (Eq, Show)

critObjectParser :: Object -> T.Text -> Parser (T.Text, Value)
critObjectParser o s
  | s `elem` critInvalidNames = fail "crit key is reserved"
  | otherwise                 = (\v -> (s, v)) <$> o .: s

parseCrit :: Object -> NonEmpty T.Text -> Parser CritParameters
parseCrit o = fmap CritParameters . mapM (critObjectParser o)
  -- TODO fail on duplicate strings

instance FromJSON CritParameters where
  parseJSON = withObject "crit" $ \o -> o .: "crit" >>= parseCrit o

instance ToJSON CritParameters where
  toJSON (CritParameters m) = object $ ("crit", toJSON $ fmap fst m) : toList m


data JWEHeader = JWEHeader
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
  , _jweCrit :: Maybe CritParameters
  }
  deriving (Eq, Show)

newJWEHeader :: AlgWithParams -> JWEHeader
newJWEHeader alg = JWEHeader (Just alg) z z z z z z z z z z z z where z = Nothing


instance FromJSON JWEHeader where
  parseJSON = withObject "JWE" $ \o -> JWEHeader
    <$> parseJSON (Object o)
    <*> o .: "enc"
    <*> o .:? "zip"
    <*> o .:? "jku"
    <*> o .:? "jwk"
    <*> o .:? "kid"
    <*> o .:? "x5u"
    <*> o .:? "x5c"
    <*> o .:? "x5t"
    <*> o .:? "x5t#S256"
    <*> o .:? "typ"
    <*> o .:? "cty"
    <*> (o .:? "crit" >>= mapM (parseCrit o))  -- TODO

instance ToJSON JWEHeader where
  toJSON (JWEHeader alg enc _zip jku jwk kid x5u x5c x5t x5tS256 typ cty crit) =
    object $ catMaybes
      [ fmap ("enc" .=) enc
      , fmap ("zip" .=) _zip
      , fmap ("jku" .=) jku
      , fmap ("jwk" .=) jwk
      , fmap ("kid" .=) kid
      , fmap ("x5u" .=) x5u
      , fmap ("x5c" .=) x5c
      , fmap ("x5t" .=) x5t
      , fmap ("x5t#S256" .=) x5tS256
      , fmap ("typ" .=) typ
      , fmap ("cty" .=) cty
      ]
      ++ Types.objectPairs (toJSON crit)
      ++ maybe [] (Types.objectPairs . toJSON) alg

instance FromArmour T.Text Error JWEHeader where
  parseArmour s =
        first (compactErr "header")
          (B64UL.decode (L.fromStrict $ Types.pad $ T.encodeUtf8 s))
        >>= first JSONDecodeError . eitherDecode
    where
    compactErr s' = CompactDecodeError . ((s' ++ " decode failed: ") ++)

instance ToArmour T.Text JWEHeader where
  toArmour = T.decodeUtf8 . Types.unpad . B64U.encode . L.toStrict . encode


data JWERecipient = JWERecipient
  { _jweHeader :: Maybe JWEHeader -- ^ JWE Per-Recipient Unprotected Header
  , _jweEncryptedKey :: Maybe Types.Base64Octets  -- ^ JWE Encrypted Key
  }

instance FromJSON JWERecipient where
  parseJSON = withObject "JWE Recipient" $ \o -> JWERecipient
    <$> o .:? "header"
    <*> o .:? "encrypted_key"

data JWE = JWE
  { _jweProtected :: Maybe (Armour T.Text JWEHeader)
  , _jweUnprotected :: Maybe JWEHeader
  , _jweIv :: Maybe Types.Base64Octets  -- ^ JWE Initialization Vector
  , _jweAad :: Maybe Types.Base64Octets -- ^ JWE AAD
  , _jweCiphertext :: Types.Base64Octets  -- ^ JWE Ciphertext
  , _jweTag :: Maybe Types.Base64Octets  -- ^ JWE Authentication Tag
  , _jweRecipients :: [JWERecipient]
  }

instance FromJSON JWE where
  parseJSON =
    withObject "JWE JSON Serialization" $ \o -> JWE
      <$> o .:? "protected"
      <*> o .:? "unprotected"
      <*> o .:? "iv"
      <*> o .:? "aad"
      <*> o .: "ciphertext"
      <*> o .:? "tag"
      <*> o .: "recipients"
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
wrap A128KW (OctKeyMaterial (OctKeyParameters _ (Types.Base64Octets k))) m
  = return $ (A128KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES128) m
wrap A192KW (OctKeyMaterial (OctKeyParameters _ (Types.Base64Octets k))) m
  = return $ (A192KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES192) m
wrap A256KW (OctKeyMaterial (OctKeyParameters _ (Types.Base64Octets k))) m
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
wrapAESGCM f enc (OctKeyMaterial (OctKeyParameters _ (Types.Base64Octets k))) m =
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
      let Just iv' = makeIV iv
      let m' = pad (PKCS7 $ blockSize e) m
      let c = cbcEncrypt e iv' m'
      let hmacInput = B.concat [aad, iv, c, aadLen]
      let tag = B.take kLen $ BA.pack $ BA.unpack (hmac mKey hmacInput :: HMAC h)
      return $ Right (iv, c, tag)

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
