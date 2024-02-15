-- Copyright (C) 2015, 2016  Fraser Tweedale
-- Copyright (C) 2023 Kari Pahula
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
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

module Crypto.JOSE.JWE
  (
    JWEHeader(..)

  , JWE(..)
  , newJWEHeader
  , newJWEHeaderWithAlg
  , GeneralJWE
  , FlattenedJWE
  , CompactJWE

  -- May be long lived and could be stored by application
  , CEK(..)
  , newCek

  -- Ciphertext creation
  , encryptRandom
  , encryptNonce

  -- CEK encryption
  , wrapForRecipients
  , wrapForSingleRecipient

  , buildJWE

  -- Decryption helpers
  , clearBlinders
  , generateBlinders

  -- CEK decryption
  , unwrap

  -- Ciphertext decryption
  , decryptJWE
  ) where

import Control.Applicative ((<|>))
import Control.Monad (when)
import Control.Monad.Except (MonadError)
import Data.Foldable (fold)
import Data.Maybe (catMaybes, fromMaybe, listToMaybe)
import Data.Monoid ((<>))
import qualified Data.Set as Set

import Control.Lens hiding ((.=))
import Control.Lens.Traversal
import Control.Lens.Cons.Extras (recons)
import Control.Monad.Error.Lens (throwing, throwing_)
import Data.Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.List.NonEmpty (NonEmpty)
import Data.Proxy
import Data.Word (Word8)

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Data.Padding
import Crypto.Error
import Crypto.Hash
import Crypto.MAC.HMAC
import Crypto.PubKey.MaskGenFunction
import Crypto.PubKey.RSA (generateBlinder)
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.PubKey.RSA.OAEP as OAEP

import Crypto.JOSE.AESKW
import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import Crypto.JOSE.Header -- (HasParams(..), HeaderParam, Protection, ProtectionIndicator)
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS (CompactJWS, JWSHeader)
import qualified Crypto.JOSE.Types as Types
import Crypto.JOSE.Types.URI
import qualified Crypto.JOSE.Types.Internal as Types


{-| JSON Web Encryption (JWE) represents encrypted content using JSON-
based data structures.  It consists of a symmetric key (CEK) and a
message encrypted with it and it can have one or more recipients, each
of which have different algorithms for communicating the encrypted
key.

These two encryption steps are divided between the Enc and Alg types
and Alg is further divided to AlgOnly and AlgWithParams.

For the first stage, the following data is required:
    * Enc choice
    * CEK (Content Encryption Key) (can be reused)
    * IV (Initialization Vector) (random or nonce)
    * AAD (Additional Authenticated Data) if it's used
    * Protected header values
    * Message to be encrypted

These are used to compute the ciphertext and tag, which are common to
all recipients.

For each recipient (one or more):
    * Alg choice (user choice)
    * Alg parameters (computed if needed)
    * Public key (for most Algs)
    * Encrypted key (CEK from above, encrypted with Alg)

The encrypted key is not used if the alg is 'Dir' or 'ECDHESAlg'.

Decryption is done by first decrypting CEK from recipients' data.  For
repeated uses of the same CEK this can be skipped.  The second stage
is the use CEK to decrypt ciphertext to get the payload.  The
authentication tag is used to verify the contents and if it doesn't
match the payload is discarded.

* Encrypt

> let enc = A128CBC_HS256
> let header :: JWEHeader () = newJWEHeaderWithAlg enc RSA_OAEP
> cek <- newCek enc
> runJOSE $ do
>   encryptedMessage <- encryptRandom header cek Nothing "Avoid success at all costs."
>   wrapped <- wrapForSingleRecipient header cek recipientJwk
>   return $ encodeCompact $ buildJWE (Identity wrapped) encryptedMessage

* Decrypt

> runJOSE $ do
>   jwe :: CompactJWE JWEHeader <- generateBlinders recipientJwk =<< decodeCompact raw
>   cek <- either throwError return $ runIdentity $ unwrap recipientJwk jwe
>   decryptJWE cek jwe
-}


critInvalidNames :: [T.Text]
critInvalidNames =
  [ "alg" , "enc" , "zip" , "jku" , "jwk" , "kid"
  , "x5u" , "x5c" , "x5t" , "x5t#S256" , "typ" , "cty" , "crit" ]

newtype CritParameters = CritParameters (NonEmpty (T.Text, Value))
  deriving (Eq, Show)


data JWEHeader p = JWEHeader
  { _jweHeaderAlg :: Maybe (HeaderParam p AlgWithParams)
  , _jweHeaderEnc :: HeaderParam p Enc
  , _jweHeaderZip :: Maybe T.Text  -- protected header only  "DEF" (DEFLATE) defined
  , _jweHeaderJku :: Maybe (HeaderParam p Types.URI)
  , _jweHeaderJwk :: Maybe (HeaderParam p JWK)
  , _jweHeaderKid :: Maybe (HeaderParam p T.Text)
  , _jweHeaderX5u :: Maybe (HeaderParam p Types.URI)
  , _jweHeaderX5c :: Maybe (HeaderParam p (NonEmpty Types.SignedCertificate))
  , _jweHeaderX5t :: Maybe (HeaderParam p Types.Base64SHA1)
  , _jweHeaderX5tS256 :: Maybe (HeaderParam p Types.Base64SHA256)
  , _jweHeaderTyp :: Maybe (HeaderParam p T.Text)  -- ^ Content Type (of object)
  , _jweHeaderCty :: Maybe (HeaderParam p T.Text)  -- ^ Content Type (of payload)
  , _jweHeaderCrit :: Maybe (NonEmpty T.Text)
  }
  deriving (Eq, Show)
makeLenses ''JWEHeader

class HasJWEHeader a where
  jweHeader :: Lens' (a p) (JWEHeader p)

instance HasJWEHeader JWEHeader where
  jweHeader = id


-- | Construct a new JWE header with protected "enc" field set.
newJWEHeader :: ProtectionIndicator p => Enc -> JWEHeader p
newJWEHeader enc =
  JWEHeader z (HeaderParam getProtected enc) z z z z z z z z z z z
  where z = Nothing


-- | Convenience function for the common case when "alg" is needed as
-- protected field as well.
newJWEHeaderWithAlg :: ProtectionIndicator p => Enc -> SimpleAlg -> JWEHeader p
newJWEHeaderWithAlg enc alg' =
  newJWEHeader enc & jweHeaderAlg .~ Just (HeaderParam getProtected $ SimpleAlg alg')


instance HasParams JWEHeader where
  parseParamsFor proxy hp hu =
    JWEHeader
    <$> (do
            let parseAlgParams alg' = case algType alg' of
                  Right (SimpleAlgOnly a) -> pure $ SimpleAlg a
                  Right (ECDHESAlgOnly a) -> ECDHESAlg a <$> parseJSON (Object $ fold hp <> fold hu)
                  Right (AESGCMAlgOnly a) -> AESGCMAlg a <$> parseJSON (Object $ fold hp <> fold hu)
                  Right (PBES2AlgOnly a) -> PBES2Alg a <$> parseJSON (Object $ fold hp <> fold hu)
                  _ -> fail $ "unrecognised value; expected: " <> knownAlgsMsg
            alg' <- (fmap . fmap . fmap) parseAlgParams (headerOptional "alg" hp hu)
            case alg' of
              Just alg'' -> fmap Just $ flip fmap alg'' . const <$> view param alg''
              Nothing -> pure Nothing
        )
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
  params (JWEHeader alg' enc' zip' jku' jwk' kid' x5u' x5c' x5t' x5tS256' typ' cty' crit') =
    [               (view isProtected enc',     "enc" .= view param enc') ] <>
      case alg' of
        Nothing -> []
        Just alg'' ->
          (map ((view isProtected alg'',)) $
            (\x -> case x of Object o -> KeyMap.toList o ; _ -> mempty) $ toJSON $ view param alg'')
    <>
    catMaybes
      [ fmap (\p -> (True, "zip" .= p)) zip'
      , fmap (\p -> (view isProtected p, "jku" .= views param uriToJSON p)) jku'
      , fmap (\p -> (view isProtected p, "jwk" .= view (param . asPublicKey) p)) jwk'
      , fmap (\p -> (view isProtected p, "kid" .= view param p)) kid'
      , fmap (\p -> (view isProtected p, "x5u" .= views param uriToJSON p)) x5u'
      , fmap (\p -> (view isProtected p, "x5c" .= fmap Types.Base64X509 (view param p))) x5c'
      , fmap (\p -> (view isProtected p, "x5t" .= view param p)) x5t'
      , fmap (\p -> (view isProtected p, "x5t#S256" .= view param p)) x5tS256'
      , fmap (\p -> (view isProtected p, "typ" .= view param p)) typ'
      , fmap (\p -> (view isProtected p, "cty" .= view param p)) cty'
      , fmap (\p -> (True, "crit" .= p)) crit'
      ]


data JWERecipient p a = JWERecipient
  { _jweBlinder :: Maybe RSA.Blinder -- ^ Blinder to use for decrypt
  , _jweHeader :: a p -- ^ Aggregate header from shared protected,
                      -- shared unprotected and per-recipient
                      -- unprotected headers
  -- | JWE Encrypted Key.  All but "dir" and "ECDH-ES" algs use it.
  , _jweEncryptedKey :: Maybe Types.Base64Octets
  }

parseRecipient
  :: (HasParams a, ProtectionIndicator p)
  => Maybe Object -> Maybe Object -> Object -> Parser (JWERecipient p a)
parseRecipient hp hu o = do
  hr <- o .:? "header"
  let keysHr = Set.fromList $ foldMap KeyMap.keys hr
      keysHu = Set.fromList $ foldMap KeyMap.keys hu
      keysHp = Set.fromList $ foldMap KeyMap.keys hp
  -- May not be optimal but n is expected to be small
  when (any (not . Set.null . uncurry Set.intersection)
        [ (keysHr, keysHu)
        , (keysHr, keysHp)
        , (keysHu, keysHp)
        ] ) $ fail "duplicate header fields"
  JWERecipient Nothing
    <$> parseParams hp (hu <> hr)
    <*> o .:? "encrypted_key"


data JWE t p a = JWE
  { _protectedRaw :: Maybe T.Text       -- ^ Encoded protected header, if available
    -- | JWE Initialization Vector.
    --
    -- In CBC mode, it's expected that the initialization vectors are
    -- random, but it's less sensitive about IV reuse.
    --
    -- In GCM mode, it's expected that an IV is never reused and since
    -- it's only 96 bits long, using random values may run into the
    -- birthday problem.
  , _jweIv :: Maybe Types.Base64Octets
  , _jweAad :: Maybe Types.Base64Octets -- ^ JWE AAD
  , _jweCiphertext :: Types.Base64Octets  -- ^ JWE Ciphertext
  , _jweTag :: Maybe Types.Base64Octets  -- ^ JWE Authentication Tag
  , _jweRecipients :: t (JWERecipient p a)
  }
makeLenses ''JWE

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

instance HasParams a => ToCompact (JWE Identity () a) where
  toCompact jwe =
    [ view recons $ maybe "" T.encodeUtf8 $ _protectedRaw jwe
    , maybe mempty (\(Types.Base64Octets x) -> review Types.base64url x) $
      _jweEncryptedKey $ runIdentity $ _jweRecipients jwe
    , maybe mempty (\(Types.Base64Octets x) -> review Types.base64url x) $ _jweIv jwe
    , (\(Types.Base64Octets x) -> review Types.base64url x) $ _jweCiphertext jwe
    , maybe mempty (\(Types.Base64Octets x) -> review Types.base64url x) $ _jweTag jwe
    ]


newtype CEK = CEK B.ByteString
  deriving (Show)


keyLen :: Enc -> Int
keyLen A128CBC_HS256 = 32
keyLen A192CBC_HS384 = 48
keyLen A256CBC_HS512 = 64
keyLen A128GCM = 16
keyLen A192GCM = 24
keyLen A256GCM = 32

-- | Generate a new symmetric key (CEK) of appropriate length for an
-- Enc.
--
-- With IV value use, it's possible to reuse the key.  It's up to the
-- application policy to determine how long it can be reused.
newCek :: MonadRandom m => Enc -> m CEK
newCek = fmap CEK . getRandomBytes . keyLen


-- | Encryption algorithm, protected header, AAD, IV, tag, ciphertext
type EncryptedMessage =
  ( T.Text -- ^ protected header
  , Types.Base64Octets -- ^ IV
  , Maybe Types.Base64Octets -- ^ AAD
  , Types.Base64Octets -- ^ ciphertext
  , Types.Base64Octets -- ^ tag
  )

-- | Encrypt with random IV.  Required for CBC mode, for GCM mode
-- 'encryptNonce' is recommended instead.
encryptRandom
  :: ( Cons s s Word8 Word8, AsEmpty s
     , HasParams a,  HasJWEHeader a
     , MonadRandom m, MonadError e m, AsError e
     , ProtectionIndicator p
     )
  => a p
  -> CEK
  -> Maybe B.ByteString -- ^ AAD.  Leave empty for Compact JWE.
  -> s -- ^ Message
  -> m EncryptedMessage
encryptRandom h (CEK cek) aad msg = do
  let enc' = view (jweHeader . jweHeaderEnc . param) h
      ivSize = case enc' of
        A128CBC_HS256 -> 16
        A192CBC_HS384 -> 16
        A256CBC_HS512 -> 16
        A128GCM -> 12
        A192GCM -> 12
        A256GCM -> 12
      pRaw = view recons (protectedParamsEncoded h)
      aad' = pRaw <> foldMap (("." <>) . review Types.base64url) aad
  iv <- getRandomBytes ivSize
  (tag, ciphertext) <- encrypt enc' cek iv (view recons msg) aad'
  pure ( T.decodeLatin1 pRaw
       , Types.Base64Octets iv
       , Types.Base64Octets <$> aad
       , Types.Base64Octets ciphertext
       , Types.Base64Octets tag
       )

-- | Encrypt using nonce value for IV.  Recommended for GCM mode, not
-- usable for CBC.  It's caller's responsibility to use unique nonce
-- for each JWE.
encryptNonce
  :: ( Cons s s Word8 Word8
     , HasParams a, AsError e, MonadError e m, HasJWEHeader a, ProtectionIndicator p
     )
  => a p
  -> CEK
  -> Maybe B.ByteString -- ^ AAD.  Leave empty for Compact JWE.
  -> Types.SizedBase64Integer -- ^ Nonce
  -> s -- ^ Message
  -> m EncryptedMessage
encryptNonce h (CEK cek) aad (Types.SizedBase64Integer w nonce) msg = do
  let
    enc' = view (jweHeader . jweHeaderEnc . param) h
    iv = Types.sizedIntegerToBS w nonce
    pRaw = view recons (protectedParamsEncoded h)
    aad' = pRaw <> foldMap (("." <>) . review Types.base64url) aad
  when (enc' `elem` [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512]) $
    throwing _AlgorithmMismatch "Nonce IV can't be used with CBC mode"
  when (w /= 96) $ throwing _AlgorithmMismatch "Nonce must be 96 bits"
  (tag, ciphertext) <- encrypt enc' cek iv (view recons msg) aad'
  pure ( T.decodeLatin1 pRaw
       , Types.Base64Octets iv
       , Types.Base64Octets <$> aad
       , Types.Base64Octets ciphertext
       , Types.Base64Octets tag
       )


-- | Encrypt the CEK for use with recipients.  The resulting
-- recipients can be reused for the same CEK for other JWE messages.
wrapForRecipients
  :: ( HasParams a, HasJWEHeader a
     , AsError e, MonadError e m, MonadRandom m
     , Traversable t
     , ProtectionIndicator p
     )
  => CEK
  -> t (AlgOnly, JWK, a p)
  -> m (t (JWERecipient p a))
wrapForRecipients (CEK cek) = traverse $ \(alg', j, h) -> do
  (alg'', encryptedKey) <- wrap alg' (view jwkMaterial j) cek
  pure $ JWERecipient Nothing
    (h &
     jweHeader . jweHeaderAlg .~ Just (HeaderParam (fromMaybe getProtected getUnprotected) alg''))
    (Just $ Types.Base64Octets encryptedKey)


-- | Convenience function for encrypting CEK for single recipient.
-- Fails if "alg" is not set in the JWE header.
wrapForSingleRecipient
  :: ( HasParams a, HasJWEHeader a
     , AsError e, MonadError e m, MonadRandom m
     , ProtectionIndicator p
     )
  => a p
  -> CEK
  -> JWK
  -> m (JWERecipient p a)
wrapForSingleRecipient h cek j = do
  -- TODO this discards alg parameters
  alg' <- maybe
    (throwing _AlgorithmMismatch "No alg set in JWE header")
    (pure . algOnly . view param) $
    view (jweHeader . jweHeaderAlg) h
  runIdentity <$> wrapForRecipients cek (Identity (alg', j, h))

-- | Combine encrypted CEK with ciphertext
buildJWE
  :: (HasParams a, ProtectionIndicator p)
  => t (JWERecipient p a)
  -> EncryptedMessage
  -> JWE t p a
buildJWE recipients (pRaw, iv, aad, ciphertext, tag) =
  JWE (Just $ pRaw) (Just iv) aad ciphertext (Just tag) recipients


wrap
  :: (MonadRandom m, AsError e, MonadError e m)
  => AlgOnly
  -> KeyMaterial
  -> B.ByteString  -- ^ message (CEK to wrap)
  -> m (AlgWithParams, B.ByteString)
wrap (SimpleAlgOnly alg@RSA_OAEP) (RSAKeyMaterial k) m = do
  encryptedKey <- OAEP.encrypt (OAEP.OAEPParams SHA1 (mgf1 SHA1) Nothing) (rsaPublicKey k) m
  case encryptedKey of
    Right x -> pure (SimpleAlg alg, x)
    Left e -> throwing _RSAError e
wrap (SimpleAlgOnly RSA_OAEP) _ _ = throwing _AlgorithmMismatch "Cannot use RSA_OAEP with non-RSA key"
wrap (SimpleAlgOnly alg@RSA_OAEP_256) (RSAKeyMaterial k) m = do
  encryptedKey <- OAEP.encrypt (OAEP.OAEPParams SHA256 (mgf1 SHA256) Nothing) (rsaPublicKey k) m
  case encryptedKey of
    Right x -> pure (SimpleAlg alg, x)
    Left e -> throwing _RSAError e
wrap (SimpleAlgOnly RSA_OAEP_256) _ _ = throwing _AlgorithmMismatch "Cannot use RSA_OAEP_256 with non-RSA key"
wrap (SimpleAlgOnly A128KW) (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m
  = (SimpleAlg A128KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES128) m
wrap (SimpleAlgOnly A192KW) (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m
  = (SimpleAlg A192KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES192) m
wrap (SimpleAlgOnly A256KW) (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m
  = (SimpleAlg A256KW,) <$> wrapAESKW (cipherInit k :: CryptoFailable AES256) m
wrap (AESGCMAlgOnly A128GCMKW) k m = wrapAESGCM (AESGCMAlg A128GCMKW) A128GCM k m
wrap (AESGCMAlgOnly A192GCMKW) k m = wrapAESGCM (AESGCMAlg A192GCMKW) A192GCM k m
wrap (AESGCMAlgOnly A256GCMKW) k m = wrapAESGCM (AESGCMAlg A256GCMKW) A256GCM k m
wrap _ _ _ = throwing_ _AlgorithmNotImplemented

wrapAESKW
  :: (AsError e, MonadError e m, BlockCipher128 cipher)
  => CryptoFailable cipher
  -> B.ByteString -- ^ plaintext key (to be encrypted)
  -> m B.ByteString -- ^ encrypted key
wrapAESKW cipher m = case cipher of
  CryptoFailed e -> throwing _CryptoError e
  CryptoPassed cipher' -> pure (aesKeyWrap cipher' m)

wrapAESGCM
  :: (AsError e, MonadError e m, MonadRandom m)
  => (AESGCMParameters -> AlgWithParams)
  -> Enc
  -> KeyMaterial
  -> B.ByteString
  -> m (AlgWithParams, B.ByteString)
wrapAESGCM f enc (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) m = do
  -- TODO should this be nonce based instead?
  iv <- getRandomBytes 12
  (\(tag, m') -> (f (AESGCMParameters (Types.Base64Octets iv) (Types.Base64Octets tag)), m'))
    <$> encrypt enc k iv m ""
wrapAESGCM _ _ _ _ = throwing _AlgorithmMismatch "Cannot use AESGCMKW with non-Oct key"

encrypt
  :: (AsError e, MonadError e m)
  => Enc
  -> B.ByteString -- ^ key
  -> B.ByteString -- ^ IV
  -> B.ByteString  -- ^ message
  -> B.ByteString  -- ^ AAD
  -> m (B.ByteString, B.ByteString)
encrypt enc' k iv m a = do
  when (B.length k /= keyLen enc') $ throwing_ _KeySizeTooSmall
  case enc' of
    A128CBC_HS256 -> _cbcHmacEnc (Proxy :: Proxy AES128) (Proxy :: Proxy SHA256) k iv m a
    A192CBC_HS384 -> _cbcHmacEnc (Proxy :: Proxy AES192) (Proxy :: Proxy SHA384) k iv m a
    A256CBC_HS512 -> _cbcHmacEnc (Proxy :: Proxy AES256) (Proxy :: Proxy SHA512) k iv m a
    A128GCM -> _gcmEnc (Proxy :: Proxy AES128) k iv m a
    A192GCM -> _gcmEnc (Proxy :: Proxy AES192) k iv m a
    A256GCM -> _gcmEnc (Proxy :: Proxy AES256) k iv m a

_cbcHmacEnc
  :: forall c h e m. (BlockCipher c, HashAlgorithm h, AsError e, MonadError e m)
  => Proxy c
  -> Proxy h
  -> B.ByteString -- ^ key
  -> B.ByteString -- ^ IV
  -> B.ByteString -- ^ message
  -> B.ByteString -- ^ additional authenticated data
  -> m (B.ByteString, B.ByteString)  -- ^ tag and ciphertext
_cbcHmacEnc _ _ k iv m aad = do
  let
    kLen = B.length k `div` 2
    (mKey, eKey) = B.splitAt kLen k
    aadLen = B.reverse $ fst $ B.unfoldrN 8 (\x -> Just (fromIntegral x, x `div` 256)) (B.length aad * 8)
  case cipherInit eKey of
    CryptoFailed _ -> throwing_ _AlgorithmNotImplemented -- FIXME
    CryptoPassed (e :: c) -> do
      case makeIV iv of
        Nothing -> throwing _CryptoError CryptoError_IvSizeInvalid
        Just iv' -> do
          let m' = pad (PKCS7 $ blockSize e) m
          let c = cbcEncrypt e iv' m'
          let hmacInput = B.concat [aad, iv, c, aadLen]
          let tag = BA.convert $ BA.takeView (hmac mKey hmacInput :: HMAC h) kLen
          pure (tag, c)

_gcmEnc
  :: forall c e m. (BlockCipher c, AsError e, MonadError e m)
  => Proxy c
  -> B.ByteString -- ^ key
  -> B.ByteString -- ^ IV
  -> B.ByteString -- ^ message
  -> B.ByteString -- ^ additional authenticated data
  -> m (B.ByteString, B.ByteString)  -- ^ tag and ciphertext
_gcmEnc _ k iv m aad = do
  case cipherInit k of
    CryptoFailed _ -> throwing_ _AlgorithmNotImplemented -- FIXME
    CryptoPassed (e :: c) -> case aeadInit AEAD_GCM e iv of
      CryptoFailed _ -> throwing_ _AlgorithmNotImplemented -- FIXME
      CryptoPassed aead -> do
        let m' = pad (PKCS7 $ blockSize e) m
        let (c, aeadFinal) = aeadEncrypt (aeadAppendHeader aead aad) m'
        let tag = BA.pack $ BA.unpack $ aeadFinalize aeadFinal 16
        pure (tag, c)


-- | Create blinder parameters to mask an RSA private key from side
-- channel attacks.  If in doubt call this before decrypt.
generateBlinders
  :: ( Each (t (JWERecipient p a)) (t (JWERecipient p a)) (JWERecipient p a) (JWERecipient p a)
     , MonadRandom m
     )
  => JWK
  -> JWE t p a
  -> m (JWE t p a)
generateBlinders key = traverseOf (jweRecipients . each) $ \recipient -> do
  case view jwkMaterial key of
    RSAKeyMaterial km -> do
      let Types.Base64Integer n = view rsaN km
      blinder <- generateBlinder n
      pure $ recipient { _jweBlinder = Just blinder }
    _ -> pure recipient

clearBlinders
  :: ( Each (t (JWERecipient p a)) (t (JWERecipient p a)) (JWERecipient p a) (JWERecipient p a) )
  => JWE t p a
  -> JWE t p a
clearBlinders = over (jweRecipients . each) $ \recipient ->
  recipient { _jweBlinder = Nothing }


-- | Try to decrypt CEK for JWE recipients with private key.  It's
-- application specific how to handle partial success but if all fail
-- it should always be treated as failure.
--
-- Consider using 'generateBlinders' for RSA key use.
unwrap
  :: ( HasJWEHeader a, HasParams a, AsError e
     , Functor t
     , ProtectionIndicator p
     )
  => JWK
  -> JWE t p a
  -> t (Either e CEK)
unwrap k jwe =
  unwrap' . ((,) <*> view jweHeader . _jweHeader) <$> _jweRecipients jwe
  where
    unwrap' (recipient, header) = do
      alg' <- maybe (throwing _AlgorithmMismatch "No Alg set") (pure . view param) $
        _jweHeaderAlg header
      when (alg' == SimpleAlg Dir) $
        throwing _AlgorithmMismatch "Dir algorithm has no CEK to unwrap"
      encryptedKey <-
        maybe
          (case alg' of
             ECDHESAlg _ _ -> pure mempty
             _ -> throwing_ _JWEIntegrityFailed)
          (\(Types.Base64Octets x) -> Right x) $
          _jweEncryptedKey recipient
      let oaepDecrypt hash m = do
            privateKey <- rsaPrivateKey m
            let oaepParams = OAEP.OAEPParams hash (mgf1 hash) Nothing
            either (throwing _RSAError) (pure . CEK) $
              OAEP.decrypt (_jweBlinder recipient) oaepParams privateKey encryptedKey
      case (alg', k ^. jwkMaterial)  of
        (SimpleAlg RSA_OAEP, RSAKeyMaterial m) ->
          oaepDecrypt SHA1 m
        (SimpleAlg RSA_OAEP, _) ->
          throwing _AlgorithmMismatch "Cannot use RSA-OAEP with non-RSA key"
        (SimpleAlg RSA_OAEP_256, RSAKeyMaterial m) ->
          oaepDecrypt SHA256 m
        (SimpleAlg RSA_OAEP_256, RSAKeyMaterial m) ->
          throwing _AlgorithmMismatch "Cannot use RSA-OAEP-256 with non-RSA key"
        _ -> throwing_ _AlgorithmNotImplemented


-- | Decrypt ciphertext with the CEK.
decryptJWE
  :: ( Cons s s Word8 Word8, AsEmpty s
     , HasJWEHeader a, HasParams a
     , AsError e, MonadError e m
     , Foldable t
     , ProtectionIndicator p
     )
  => CEK
  -> JWE t p a
  -> m s
decryptJWE (CEK cek) jwe = do
  -- Any will do, it must be shared
  enc <- maybe (throwing_ _AlgorithmNotImplemented) pure $ listToMaybe $
    foldr (\t -> ((view (jweHeader . jweHeaderEnc . param) $ _jweHeader t):)) [] $ _jweRecipients jwe
  let
    iv = maybe "" (\(Types.Base64Octets x) -> x) $ _jweIv jwe
    aad = case (_protectedRaw jwe, _jweAad jwe) of
      (Just h, Just (Types.Base64Octets x)) -> h <> "." <> T.decodeLatin1 (review Types.base64url x)
      (Just h, _) -> h
      (_, Just (Types.Base64Octets x)) -> T.decodeLatin1 (review Types.base64url x)
      _ -> ""
    ciphertext = (\(Types.Base64Octets x) -> x) $ _jweCiphertext jwe
    tag = maybe "" (\(Types.Base64Octets x) -> x) $ _jweTag jwe
  view recons <$> decrypt enc cek aad iv ciphertext tag


decrypt
  :: (MonadError e m, AsError e)
  => Enc
  -> B.ByteString -- ^ key
  -> T.Text -- ^ additional authenticated data
  -> B.ByteString -- ^ iv
  -> B.ByteString -- ^ ciphertext
  -> B.ByteString -- ^ tag
  -> m B.ByteString
decrypt A128CBC_HS256 k a i c t = case B.length k of
  32 -> _cbcHmacDec (Proxy :: Proxy AES128) (Proxy :: Proxy SHA256) k a i c t
  _ -> throwing_ _KeySizeTooSmall
decrypt A192CBC_HS384 k a i c t = case B.length k of
  48 -> _cbcHmacDec (Proxy :: Proxy AES192) (Proxy :: Proxy SHA384) k a i c t
  _ -> throwing_ _KeySizeTooSmall
decrypt A256CBC_HS512 k a i c t = case B.length k of
  64 -> _cbcHmacDec (Proxy :: Proxy AES256) (Proxy :: Proxy SHA512) k a i c t
  _ -> throwing_ _KeySizeTooSmall
decrypt _ _ _ _ _ _ = throwing_ _AlgorithmNotImplemented

_cbcHmacDec
  :: forall c e h m. (BlockCipher c, HashAlgorithm h , AsError e, MonadError e m)
  => Proxy c
  -> Proxy h
  -> B.ByteString -- ^ key
  -> T.Text -- ^ additional authenticated data
  -> B.ByteString -- ^ iv
  -> B.ByteString -- ^ ciphertext
  -> B.ByteString -- ^ tag
  -> m B.ByteString -- ^ message
_cbcHmacDec _ _ k aadText iv c tag = do
  let
    aad = T.encodeUtf8 aadText
    kLen = B.length k `div` 2
    (mKey, eKey) = B.splitAt kLen k
    aadLen = B.reverse $ fst $ B.unfoldrN 8 (\x -> Just (fromIntegral x, x `div` 256)) (B.length aad * 8)
  case (cipherInit eKey, makeIV iv) of
    (_, Nothing) -> throwing _CryptoError CryptoError_IvSizeInvalid
    (CryptoPassed (e :: c), Just iv') -> do
      let m' = cbcDecrypt e iv' c
      m <- case unpad (PKCS7 $ blockSize e) m' of
        Nothing -> throwing_ _JWEIntegrityFailed
        Just m -> pure m
      let hmacInput = B.concat [aad, iv, c, aadLen]
      let tag' = BA.convert $ BA.takeView (hmac mKey hmacInput :: HMAC h) kLen
      let tag'' :: B.ByteString = BA.convert $ BA.takeView tag kLen
      -- Check the integrity of aad+ciphertext
      when (tag'' /= tag') $ throwing_ _JWEIntegrityFailed
      -- aad and e are considered valid
      pure m
    _ -> throwing_ _AlgorithmNotImplemented
