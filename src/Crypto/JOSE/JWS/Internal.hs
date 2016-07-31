-- Copyright (C) 2013, 2014, 2015, 2016  Fraser Tweedale
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
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_HADDOCK hide #-}

module Crypto.JOSE.JWS.Internal where

import Control.Applicative ((<|>))
import Data.Bifunctor
import Data.Maybe
import Data.Monoid ((<>))

import Control.Lens hiding ((.=))
import Control.Monad.Except (MonadError(throwError))
import Data.Aeson
import qualified Data.Aeson.Parser as P
import Data.Aeson.Types
import qualified Data.Attoparsec.ByteString.Lazy as A
import Data.Byteable
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.HashMap.Strict as M
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types


critInvalidNames :: [T.Text]
critInvalidNames = [
  "alg"
  , "jku"
  , "jwk"
  , "x5u"
  , "x5t"
  , "x5t#S256"
  , "x5c"
  , "kid"
  , "typ"
  , "cty"
  , "crit"
  ]

newtype CritParameters = CritParameters (NonEmpty T.Text)
  deriving (Eq, Show)

critObjectParser :: Object -> T.Text -> Parser T.Text
critObjectParser o s
  | s `elem` critInvalidNames = fail "crit key is reserved"
  | not (s `M.member` o)      = fail "crit key is not present in headers"
  | otherwise                 = pure s

parseCrit :: Object -> NonEmpty T.Text -> Parser CritParameters
parseCrit o = fmap CritParameters . mapM (critObjectParser o)
  -- TODO fail on duplicate strings

instance FromJSON CritParameters where
  parseJSON = fmap CritParameters . parseJSON

instance ToJSON CritParameters where
  toJSON (CritParameters a) = toJSON a


-- | JWS Header data type.
--
data JWSHeader = JWSHeader
  { headerAlg :: HeaderParam JWA.JWS.Alg
  , headerJku :: Maybe (HeaderParam Types.URI)  -- ^ JWK Set URL
  , headerJwk :: Maybe (HeaderParam JWK)
  , headerKid :: Maybe (HeaderParam String)  -- ^ interpretation unspecified
  , headerX5u :: Maybe (HeaderParam Types.URI)
  , headerX5c :: Maybe (HeaderParam (NonEmpty Types.Base64X509))
  , headerX5t :: Maybe (HeaderParam Types.Base64SHA1)
  , headerX5tS256 :: Maybe (HeaderParam Types.Base64SHA256)
  , headerTyp :: Maybe (HeaderParam String)  -- ^ Content Type (of object)
  , headerCty :: Maybe (HeaderParam String)  -- ^ Content Type (of payload)
  , headerCrit :: Maybe CritParameters
  }
  deriving (Eq, Show)

data Protection = Protected | Unprotected
  deriving (Eq, Show)

data HeaderParam a = HeaderParam Protection a
  deriving (Eq, Show)

protection :: HeaderParam a -> Protection
protection (HeaderParam b _) = b

param :: HeaderParam a -> a
param (HeaderParam _ a) = a

-- | Construct a minimal header with the given algorithm
--
newJWSHeader :: (Protection, JWA.JWS.Alg) -> JWSHeader
newJWSHeader alg = JWSHeader (uncurry HeaderParam alg) z z z z z z z z z z
  where z = Nothing


{- TODO
checkHeaders :: Signature -> Either Error Signature
checkHeaders sig@(Signature h h' _) = do
  when (isJust $ h' >>= headerCrit) (Left JWSCritUnprotected) --test
      -}

headerOptional
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe (HeaderParam a))
headerOptional k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (Just v, Nothing)   -> Just . HeaderParam Protected <$> parseJSON v
  (Nothing, Just v)   -> Just . HeaderParam Unprotected <$> parseJSON v
  (Nothing, Nothing)  -> pure Nothing

headerOptionalProtected
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe a)
headerOptionalProtected k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (_, Just _) -> fail $ "header must be protected: " ++ show k
  (Just v, _) -> Just <$> parseJSON v
  _           -> pure Nothing

headerRequired
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (HeaderParam a)
headerRequired k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (Just v, Nothing)   -> HeaderParam Protected <$> parseJSON v
  (Nothing, Just v)   -> HeaderParam Unprotected <$> parseJSON v
  (Nothing, Nothing)  -> fail $ "missing required header " ++ show k

parseHeader :: Maybe Object -> Maybe Object -> Parser JWSHeader
parseHeader hp hu = JWSHeader
  <$> headerRequired "alg" hp hu
  <*> headerOptional "jku" hp hu
  <*> headerOptional "jwk" hp hu
  <*> headerOptional "kid" hp hu
  <*> headerOptional "x5u" hp hu
  <*> headerOptional "x5t" hp hu
  <*> headerOptional "x5t#S256" hp hu
  <*> headerOptional "x5c" hp hu
  <*> headerOptional "typ" hp hu
  <*> headerOptional "cty" hp hu
  <*> (headerOptionalProtected "crit" hp hu
    >>= mapM (parseCrit (fromMaybe mempty hp <> fromMaybe mempty hu)))

-- | This instance will only work for a "complete" header, i.e.
-- "alg" field is present.  It assumes the header is the protected
-- header.
--
instance FromJSON JWSHeader where
  parseJSON = withObject "Protected JWS Header (complete)"
    (\o -> parseHeader (Just o) Nothing)


data Signature = Signature
  { _protectedRaw :: (Maybe T.Text)      -- ^ Encoded protected header, if available
  , _header :: JWSHeader          -- ^ Header
  , _signature :: Types.Base64Octets  -- ^ Signature
  }
  deriving (Show)
makeLenses ''Signature

instance Eq Signature where
  Signature r h s == Signature r' h' s' =
    h == h' && s == s' && f r r'
    where
    f Nothing Nothing = True
    f (Just t) (Just t') = t == t'
    f Nothing (Just t') = BSL.toStrict (protectedParamsEncoded h) == T.encodeUtf8 t'
    f (Just t) Nothing = T.encodeUtf8 t == BSL.toStrict (protectedParamsEncoded h')

instance FromJSON Signature where
  parseJSON = withObject "signature" (\o -> Signature
    <$> (Just <$> (o .: "protected" <|> pure ""))  -- raw protected header
    <*> do
      hpB64 <- o .:? "protected"
      hp <- maybe
        (pure Nothing)
        (withText "base64url-encoded header params"
          (Types.parseB64Url (maybe
            (fail "protected header contains invalid JSON")
            pure . decode . BSL.fromStrict)))
        hpB64
      hu <- o .:? "header"
      parseHeader hp hu
    <*> o .: "signature"
    )

instance ToJSON Signature where
  toJSON (Signature _ h sig) =
    let
      pro = case protectedParamsEncoded h of
        "" -> id
        bs -> ("protected" .= String (T.decodeUtf8 (BSL.toStrict bs)) :)
      unp = case unprotectedParams h of
        Nothing -> id
        Just o -> ("header" .= o :)
    in
      object $ (pro . unp) [("signature" .= sig)]


class HasParams a where
  params :: a -> [(Protection, Pair)]

instance HasParams JWSHeader where
  params (JWSHeader alg jku jwk kid x5u x5c x5t x5tS256 typ cty crit) =
    catMaybes
      [ Just (protection alg,      "alg" .= param alg)
      , fmap (\p -> (protection p, "jku" .= param p)) jku
      , fmap (\p -> (protection p, "jku" .= param p)) jku
      , fmap (\p -> (protection p, "jwk" .= param p)) jwk
      , fmap (\p -> (protection p, "kid" .= param p)) kid
      , fmap (\p -> (protection p, "x5u" .= param p)) x5u
      , fmap (\p -> (protection p, "x5c" .= param p)) x5c
      , fmap (\p -> (protection p, "x5t" .= param p)) x5t
      , fmap (\p -> (protection p, "x5t#S256" .= param p)) x5tS256
      , fmap (\p -> (protection p, "typ" .= param p)) typ
      , fmap (\p -> (protection p, "cty" .= param p)) cty
      , fmap (\p -> (Protected,    "crit" .= p)) crit
      ]


protectedParams :: HasParams a => a -> Maybe Value {- ^ Object -}
protectedParams h =
  case (map snd . filter ((== Protected) . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)

protectedParamsEncoded :: HasParams a => a -> BSL.ByteString
protectedParamsEncoded h =
  case protectedParams h of
    Nothing -> ""
    Just o  -> (Types.unpad . B64UL.encode . encode) o

unprotectedParams :: HasParams a => a -> Maybe Value {- ^ Object -}
unprotectedParams h =
  case (map snd . filter ((== Unprotected) . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)


-- | JSON Web Signature data type.  Consists of a payload and a
-- (possibly empty) list of signatures.
--
data JWS = JWS Types.Base64Octets [Signature]
  deriving (Eq, Show)

instance FromJSON JWS where
  parseJSON v =
    withObject "JWS JSON serialization" (\o -> JWS
      <$> o .: "payload"
      <*> o .: "signatures") v
    <|> withObject "Flattened JWS JSON serialization" (\o ->
      if M.member "signatures" o
      then fail "\"signatures\" member MUST NOT be present"
      else (\p s -> JWS p [s]) <$> o .: "payload" <*> parseJSON v) v

instance ToJSON JWS where
  toJSON (JWS p ss) = object ["payload" .= p, "signatures" .= ss]

-- | Construct a new (unsigned) JWS
--
newJWS :: BS.ByteString -> JWS
newJWS msg = JWS (Types.Base64Octets msg) []

-- | Payload of a JWS, as a lazy bytestring.
--
jwsPayload :: JWS -> BSL.ByteString
jwsPayload (JWS (Types.Base64Octets s) _) = BSL.fromStrict s

signingInput :: Either T.Text JWSHeader -> Types.Base64Octets -> BS.ByteString
signingInput h p = BS.intercalate "."
  [ either T.encodeUtf8 (BSL.toStrict . protectedParamsEncoded) h
  , toBytes p
  ]

-- Convert JWS to compact serialization.
--
-- The operation is defined only when there is exactly one
-- signature and returns Nothing otherwise
--
instance ToCompact JWS where
  toCompact (JWS p [Signature raw h sig]) =
    case unprotectedParams h of
      Nothing -> pure
        [ BSL.fromStrict $ signingInput (maybe (Right h) Left raw) p
        , BSL.fromStrict $ toBytes sig
        ]
      Just _ -> throwError $ review _CompactEncodeError $
        "cannot encode a compact JWS with unprotected headers"
  toCompact (JWS _ sigs) = throwError $ review _CompactEncodeError $
    "cannot compact serialize JWS with " ++ show (length sigs) ++ " sigs"

instance FromCompact JWS where
  fromCompact xs = case xs of
    [h, p, s] ->
      let
        m = do
          h' <- first (compactErr "base64url") (B64UL.decode (Types.pad h))
                >>= decodeS "protected"
          p' <- decodeS "payload" (quote p)
          s' <- decodeS "signature" (quote s)
          pure $ JWS p' [Signature (Just (T.decodeUtf8 (BSL.toStrict h))) h' s']
      in either (throwError . review _Error) pure m
    xs' -> throwError $ compactErr "compact representation"
      $ "expected 3 parts, got " ++ show (length xs')
    where
      compactErr s = review _CompactDecodeError . ((s ++ " decode failed: ") ++)
      quote s = BSL.intercalate s ["\"", "\""]
      decodeS desc s =
        first (compactErr desc) (A.eitherResult $ A.parse P.value s)
          >>= first (review _JSONDecodeError) . parseEither parseJSON


-- §5.1. Message Signing or MACing

-- | Create a new signature on a JWS.
--
signJWS
  :: MonadRandom m
  => JWS      -- ^ JWS to sign
  -> JWSHeader  -- ^ Header for signature
  -> JWK      -- ^ Key with which to sign
  -> m (Either Error JWS) -- ^ JWS with new signature appended
signJWS (JWS p sigs) h k =
  fmap appendSig
  <$> sign (param (headerAlg h)) (k ^. jwkMaterial) (signingInput (Right h) p)
  where
    appendSig sig = JWS p (Signature Nothing h (Types.Base64Octets sig):sigs)


-- | Validation policy.
--
data ValidationPolicy
  = AnyValidated
  -- ^ One successfully validated signature is sufficient
  | AllValidated
  -- ^ All signatures in all configured algorithms must be validated.
  -- No signatures in configured algorithms is also an error.
  deriving (Eq)

data ValidationSettings = ValidationSettings
  { _validationSettingsAlgorithms :: S.Set JWA.JWS.Alg
  , _validationSettingsValidationPolicy :: ValidationPolicy
  }
makeClassy ''ValidationSettings

class HasAlgorithms s where
  algorithms :: Lens' s (S.Set JWA.JWS.Alg)
class HasValidationPolicy s where
  validationPolicy :: Lens' s ValidationPolicy

instance HasValidationSettings a => HasAlgorithms a where
  algorithms = validationSettingsAlgorithms
instance HasValidationSettings a => HasValidationPolicy a where
  validationPolicy = validationSettingsValidationPolicy

defaultValidationSettings :: ValidationSettings
defaultValidationSettings = ValidationSettings
  ( S.fromList
    [ JWA.JWS.HS256, JWA.JWS.HS384, JWA.JWS.HS512
    , JWA.JWS.RS256, JWA.JWS.RS384, JWA.JWS.RS512
    , JWA.JWS.ES256, JWA.JWS.ES384, JWA.JWS.ES512
    , JWA.JWS.PS256, JWA.JWS.PS384, JWA.JWS.PS512
    ] )
  AllValidated


-- | Verify a JWS.
--
-- Verification succeeds if any signature on the JWS is successfully
-- validated with the given 'Key'.
--
-- If only specific signatures need to be validated, and the
-- 'ValidationPolicy' argument is not enough to express this,
-- the caller is responsible for removing irrelevant signatures
-- prior to calling 'verifyJWS'.
--
verifyJWS
  :: (HasAlgorithms a, HasValidationPolicy a, AsError e, MonadError e m)
  => a
  -> JWK
  -> JWS
  -> m ()
verifyJWS conf k (JWS p sigs) =
  let
    algs :: S.Set JWA.JWS.Alg
    algs = conf ^. algorithms
    policy :: ValidationPolicy
    policy = conf ^. validationPolicy
    shouldValidateSig = (`elem` algs) . param . headerAlg . view header
    applyPolicy AnyValidated xs =
      if or xs then pure () else throwError (review _JWSNoValidSignatures ())
    applyPolicy AllValidated [] = throwError (review _JWSNoSignatures ())
    applyPolicy AllValidated xs =
      if and xs then pure () else throwError (review _JWSInvalidSignature ())
    validate = (== Right True) . verifySig k p
  in
    applyPolicy policy $ map validate $ filter shouldValidateSig sigs

verifySig :: JWK -> Types.Base64Octets -> Signature -> Either Error Bool
verifySig k m (Signature raw h (Types.Base64Octets s)) =
  verify (param (headerAlg h)) (view jwkMaterial k) tbs s
  where
  tbs = signingInput (maybe (Right h) Left raw) m
