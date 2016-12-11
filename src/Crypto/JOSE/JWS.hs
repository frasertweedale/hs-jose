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

{-|

JSON Web Signature (JWS) represents content secured with digital
signatures or Message Authentication Codes (MACs) using JavaScript
Object Notation (JSON) based data structures.  It is defined in
<https://tools.ietf.org/html/rfc7515 RFC 7515>.

@
doJwsSign :: 'JWK' -> L.ByteString -> IO (Either 'Error' ('JWS' [] 'JWSHeader'))
doJwsSign jwk payload = runExceptT $ do
  alg \<- 'bestJWSAlg' jwk
  'signJWS' payload [('newJWSHeader' ('Protected', alg), jwk)]

doJwsVerify :: 'JWK' -> 'JWS' [] 'JWSHeader' -> IO (Either 'Error' ())
doJwsVerify jwk jws = runExceptT $ 'verifyJWS'' jwk jws
@

-}

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Crypto.JOSE.JWS
  (
  -- * Overview
    JWS

  -- ** Defining additional header parameters
  -- $extending

  -- * JWS creation
  , newJWSHeader
  , signJWS

  -- * JWS verification
  , verifyJWS
  , verifyJWS'

  -- ** JWS validation settings
  , defaultValidationSettings
  , ValidationSettings
  , ValidationPolicy(..)
  , HasValidationSettings(..)
  , HasAlgorithms(..)
  , HasValidationPolicy(..)

  -- * Signature data
  , signatures
  , Signature
  , header
  , signature

  -- * JWS headers
  , Alg(..)
  , HasJWSHeader(..)
  , JWSHeader

  , module Crypto.JOSE.Error
  , module Crypto.JOSE.Header
  , module Crypto.JOSE.JWK
  ) where

import Control.Applicative ((<|>))
import Data.Foldable (toList)
import Data.Maybe (catMaybes, fromMaybe)
import Data.Monoid ((<>))
import Data.List.NonEmpty (NonEmpty)
import Data.Traversable (traverse)
import Data.Word (Word8)

import Control.Lens hiding ((.=))
import Control.Lens.Cons.Extras (recons)
import Control.Monad.Except (MonadError(throwError))
import Data.Aeson
import qualified Data.ByteString as B
import qualified Data.HashMap.Strict as M
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import Crypto.JOSE.JWA.JWS
import Crypto.JOSE.JWK
import Crypto.JOSE.JWK.Store
import Crypto.JOSE.Header
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types

{- $extending

Several specifications extend JWS with additional header parameters.
The 'JWS' type is parameterised over the header type; this library
provides the 'JWSHeader' type which encompasses all the JWS header
parameters defined in RFC 7515.  To define an extended header type
declare the data type, and instances for 'HasJWSHeader' and
'HasParams'.  For example:

@
data ACMEHeader = ACMEHeader
  { _acmeJwsHeader :: 'JWSHeader'
  , _acmeNonce :: 'Types.Base64Octets'
  }

acmeJwsHeader :: Lens' ACMEHeader JWSHeader
acmeJwsHeader f s\@(ACMEHeader { _acmeJwsHeader = a}) =
  fmap (\\a' -> s { _acmeJwsHeader = a'}) (f a)

acmeNonce :: Lens' ACMEHeader Types.Base64Octets
acmeNonce f s\@(ACMEHeader { _acmeNonce = a}) =
  fmap (\\a' -> s { _acmeNonce = a'}) (f a)

instance HasJWSHeader ACMEHeader where
  jWSHeader = acmeJwsHeader

instance HasParams ACMEHeader where
  'parseParamsFor' proxy hp hu = ACMEHeader
    \<$> 'parseParamsFor' proxy hp hu
    \<*> 'headerRequiredProtected' "nonce" hp hu
  params h =
    (Protected, "nonce" .= view acmeNonce h)
    : 'params' (view acmeJwsHeader h)
  'extensions' = const ["nonce"]
@

See also:

- 'HasParams'
- 'headerRequired'
- 'headerRequiredProtected'
- 'headerOptional'
- 'headerOptionalProtected'

-}


jwsCritInvalidNames :: [T.Text]
jwsCritInvalidNames = [
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

-- | JWS Header data type.
--
data JWSHeader = JWSHeader
  { _jwsHeaderAlg :: HeaderParam Alg
  , _jwsHeaderJku :: Maybe (HeaderParam Types.URI)  -- ^ JWK Set URL
  , _jwsHeaderJwk :: Maybe (HeaderParam JWK)
  , _jwsHeaderKid :: Maybe (HeaderParam String)  -- ^ interpretation unspecified
  , _jwsHeaderX5u :: Maybe (HeaderParam Types.URI)
  , _jwsHeaderX5c :: Maybe (HeaderParam (NonEmpty Types.Base64X509))
  , _jwsHeaderX5t :: Maybe (HeaderParam Types.Base64SHA1)
  , _jwsHeaderX5tS256 :: Maybe (HeaderParam Types.Base64SHA256)
  , _jwsHeaderTyp :: Maybe (HeaderParam String)  -- ^ Content Type (of object)
  , _jwsHeaderCty :: Maybe (HeaderParam String)  -- ^ Content Type (of payload)
  , _jwsHeaderCrit :: Maybe (NonEmpty T.Text)
  }
  deriving (Eq, Show)

instance HasAlg JWSHeader where
  alg f h@(JWSHeader { _jwsHeaderAlg = a }) =
    fmap (\a' -> h { _jwsHeaderAlg = a' }) (f a)
instance HasJku JWSHeader where
  jku f h@(JWSHeader { _jwsHeaderJku = a }) =
    fmap (\a' -> h { _jwsHeaderJku = a' }) (f a)
instance HasJwk JWSHeader where
  jwk f h@(JWSHeader { _jwsHeaderJwk = a }) =
    fmap (\a' -> h { _jwsHeaderJwk = a' }) (f a)
instance HasKid JWSHeader where
  kid f h@(JWSHeader { _jwsHeaderKid = a }) =
    fmap (\a' -> h { _jwsHeaderKid = a' }) (f a)
instance HasX5u JWSHeader where
  x5u f h@(JWSHeader { _jwsHeaderX5u = a }) =
    fmap (\a' -> h { _jwsHeaderX5u = a' }) (f a)
instance HasX5c JWSHeader where
  x5c f h@(JWSHeader { _jwsHeaderX5c = a }) =
    fmap (\a' -> h { _jwsHeaderX5c = a' }) (f a)
instance HasX5t JWSHeader where
  x5t f h@(JWSHeader { _jwsHeaderX5t = a }) =
    fmap (\a' -> h { _jwsHeaderX5t = a' }) (f a)
instance HasX5tS256 JWSHeader where
  x5tS256 f h@(JWSHeader { _jwsHeaderX5tS256 = a }) =
    fmap (\a' -> h { _jwsHeaderX5tS256 = a' }) (f a)
instance HasTyp JWSHeader where
  typ f h@(JWSHeader { _jwsHeaderTyp = a }) =
    fmap (\a' -> h { _jwsHeaderTyp = a' }) (f a)
instance HasCty JWSHeader where
  cty f h@(JWSHeader { _jwsHeaderCty = a }) =
    fmap (\a' -> h { _jwsHeaderCty = a' }) (f a)
instance HasCrit JWSHeader where
  crit f h@(JWSHeader { _jwsHeaderCrit = a }) =
    fmap (\a' -> h { _jwsHeaderCrit = a' }) (f a)

class HasJWSHeader a where
  jWSHeader :: Lens' a JWSHeader

instance HasJWSHeader JWSHeader where
  jWSHeader = id

instance {-# INCOHERENT #-} HasJWSHeader a => HasAlg a where
  alg = jWSHeader . alg
instance {-# INCOHERENT #-} HasJWSHeader a => HasJku a where
  jku = jWSHeader . jku
instance {-# INCOHERENT #-} HasJWSHeader a => HasJwk a where
  jwk = jWSHeader . jwk
instance {-# INCOHERENT #-} HasJWSHeader a => HasKid a where
  kid = jWSHeader . kid
instance {-# INCOHERENT #-} HasJWSHeader a => HasX5u a where
  x5u = jWSHeader . x5u
instance {-# INCOHERENT #-} HasJWSHeader a => HasX5c a where
  x5c = jWSHeader . x5c
instance {-# INCOHERENT #-} HasJWSHeader a => HasX5t a where
  x5t = jWSHeader . x5t
instance {-# INCOHERENT #-} HasJWSHeader a => HasX5tS256 a where
  x5tS256 = jWSHeader . x5tS256
instance {-# INCOHERENT #-} HasJWSHeader a => HasTyp a where
  typ = jWSHeader . typ
instance {-# INCOHERENT #-} HasJWSHeader a => HasCty a where
  cty = jWSHeader . cty
instance {-# INCOHERENT #-} HasJWSHeader a => HasCrit a where
  crit = jWSHeader . crit


-- | Construct a minimal header with the given algorithm
--
newJWSHeader :: (Protection, Alg) -> JWSHeader
newJWSHeader a = JWSHeader (uncurry HeaderParam a) z z z z z z z z z z
  where z = Nothing


-- | Signature object containing header, and signature bytes.
--
-- If it was decoded from a serialised JWS, it "remembers" how the
-- protected header was encoded; the remembered value is used when
-- computing the signing input and when serialising the object.
--
-- The remembered value is not used in equality checks, i.e. two
-- decoded signatures with differently serialised by otherwise equal
-- protected headers, and equal signature bytes, are equal.
--
data Signature a = Signature
  (Maybe T.Text)      -- Encoded protected header, if available
  a                   -- Header
  Types.Base64Octets  -- Signature
  deriving (Show)

-- | Getter for header of a signature
header :: Getter (Signature a) a
header = to (\(Signature _ h _) -> h)

-- | Getter for signature bytes
signature :: (Cons s s Word8 Word8, AsEmpty s) => Getter (Signature a) s
signature = to (\(Signature _ _ (Types.Base64Octets s)) -> s) . recons

instance (Eq a) => Eq (Signature a) where
  Signature _ h s == Signature _ h' s' = h == h' && s == s'

instance HasParams a => FromJSON (Signature a) where
  parseJSON = withObject "signature" (\o -> Signature
    <$> (Just <$> (o .: "protected" <|> pure ""))  -- raw protected header
    <*> do
      hpB64 <- o .:? "protected"
      hp <- maybe
        (pure Nothing)
        (withText "base64url-encoded header params"
          (Types.parseB64Url (maybe
            (fail "protected header contains invalid JSON")
            pure . decode . view recons)))
        hpB64
      hu <- o .:? "header"
      parseParams hp hu
    <*> o .: "signature"
    )

instance HasParams a => ToJSON (Signature a) where
  toJSON (Signature _ h sig) =
    let
      pro = case protectedParamsEncoded h of
        "" -> id
        bs -> ("protected" .= String (T.decodeUtf8 (view recons bs)) :)
      unp = case unprotectedParams h of
        Nothing -> id
        Just o -> ("header" .= o :)
    in
      object $ (pro . unp) [("signature" .= sig)]


instance HasParams JWSHeader where
  parseParamsFor proxy hp hu = JWSHeader
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
      >>= parseCrit jwsCritInvalidNames (extensions proxy)
        (fromMaybe mempty hp <> fromMaybe mempty hu))
  params h =
    catMaybes
      [ Just (view (alg . protection) h, "alg" .= (view (alg . param) h))
      , fmap (\p -> (view protection p, "jku" .= view param p)) (view jku h)
      , fmap (\p -> (view protection p, "jwk" .= view param p)) (view jwk h)
      , fmap (\p -> (view protection p, "kid" .= view param p)) (view kid h)
      , fmap (\p -> (view protection p, "x5u" .= view param p)) (view x5u h)
      , fmap (\p -> (view protection p, "x5c" .= view param p)) (view x5c h)
      , fmap (\p -> (view protection p, "x5t" .= view param p)) (view x5t h)
      , fmap (\p -> (view protection p, "x5t#S256" .= view param p)) (view x5tS256 h)
      , fmap (\p -> (view protection p, "typ" .= view param p)) (view typ h)
      , fmap (\p -> (view protection p, "cty" .= view param p)) (view cty h)
      , fmap (\p -> (Protected,    "crit" .= p)) (view crit h)
      ]


-- | JSON Web Signature data type.  The payload can only be
-- accessed by verifying the JWS.
--
-- Parameterised by the header type, and the signature container type.
--
-- Use 'encode' and 'decode' to convert a JWS to or from JSON.
-- When encoding a @'JWS' []@ with exactly one signature, the
-- /flattened JWS JSON serialisation/ syntax is used, otherwise
-- the /general JWS JSON serialisation/ is used.
-- When decoding a @'JWS' []@ either serialisation is accepted.
--
-- @'JWS' 'Identity'@ uses the flattened JSON serialisation
-- or the /JWS compact serialisation/ (see 'decodeCompact' and
-- 'encodeCompact').
--
-- Use 'signJWS' to create a signed/MACed JWS.
--
-- Use 'verifyJWS' to verify a JWS and extract the payload.
--
data JWS t a = JWS Types.Base64Octets (t (Signature a))

instance (Eq (t (Signature a))) => Eq (JWS t a) where
  JWS p sigs == JWS p' sigs' = p == p' && sigs == sigs'

instance (Show (t (Signature a))) => Show (JWS t a) where
  show (JWS p sigs) = "JWS " <> show p <> " " <> show sigs

signatures :: Foldable t => Fold (JWS t a) (Signature a)
signatures = folding (\(JWS _ sigs) -> sigs)

instance HasParams a => FromJSON (JWS [] a) where
  parseJSON v =
    withObject "JWS JSON serialization" (\o -> JWS
      <$> o .: "payload"
      <*> o .: "signatures") v
    <|> fmap (\(JWS p (Identity s)) -> JWS p [s]) (parseJSON v)

instance HasParams a => FromJSON (JWS Identity a) where
  parseJSON =
    withObject "Flattened JWS JSON serialization" $ \o ->
      if M.member "signatures" o
      then fail "\"signatures\" member MUST NOT be present"
      else (\p s -> JWS p (pure s)) <$> o .: "payload" <*> parseJSON (Object o)

instance HasParams a => ToJSON (JWS [] a) where
  toJSON (JWS p [s]) = object $ "payload" .= p : Types.objectPairs (toJSON s)
  toJSON (JWS p ss) = object ["payload" .= p, "signatures" .= ss]

instance HasParams a => ToJSON (JWS Identity a) where
  toJSON (JWS p (Identity s)) = object $ "payload" .= p : Types.objectPairs (toJSON s)


signingInput
  :: HasParams a
  => Either T.Text a
  -> B.ByteString
  -> B.ByteString
signingInput h p = B.intercalate "."
  [ either T.encodeUtf8 (view recons . protectedParamsEncoded) h
  , review Types.base64url p
  ]

-- Convert JWS to compact serialization.
--
-- The operation is defined only when there is exactly one
-- signature and returns Nothing otherwise
--
instance HasParams a => ToCompact (JWS Identity a) where
  toCompact (JWS (Types.Base64Octets p) (Identity (Signature raw h (Types.Base64Octets sig)))) =
    case unprotectedParams h of
      Nothing -> pure
        [ view recons $ signingInput (maybe (Right h) Left raw) p
        , review Types.base64url sig
        ]
      Just _ -> throwError $ review _CompactEncodeError $
        "cannot encode a compact JWS with unprotected headers"

instance HasParams a => FromCompact (JWS Identity a) where
  fromCompact xs = case xs of
    [h, p, s] -> do
      (h', p', s') <- (,,) <$> t h <*> t p <*> t s
      let o = object [ ("payload", p'), ("protected", h'), ("signature", s') ]
      case fromJSON o of
        Error e -> throwError (compactErr e)
        Success a -> pure a
    xs' -> throwError $ compactErr $ "expected 3 parts, got " ++ show (length xs')
    where
      compactErr = review _CompactDecodeError
      t = either (throwError . compactErr . show) (pure . String)
        . T.decodeUtf8' . view recons


-- | Create a signed or MACed JWS with the given payload by
-- traversing a collection of @(header, key)@ pairs.
--
signJWS
  :: ( Cons s s Word8 Word8
     , HasJWSHeader a, HasParams a, MonadRandom m, AsError e, MonadError e m
     , Traversable t
     )
  => s          -- ^ Payload
  -> t (a, JWK) -- ^ Traversable of header, key pairs
  -> m (JWS t a)
signJWS s =
  let s' = view recons s
  in fmap (JWS (Types.Base64Octets s')) . traverse (uncurry (mkSignature s'))

mkSignature
  :: (HasJWSHeader a, HasParams a, MonadRandom m, AsError e, MonadError e m)
  => B.ByteString -> a -> JWK -> m (Signature a)
mkSignature p h k =
  Signature Nothing h . Types.Base64Octets
  <$> sign (view (alg . param) h) (k ^. jwkMaterial) (signingInput (Right h) p)


-- | Validation policy.
--
data ValidationPolicy
  = AnyValidated
  -- ^ One successfully validated signature is sufficient
  | AllValidated
  -- ^ All signatures in all configured algorithms must be validated.
  -- No signatures in configured algorithms is also an error.
  deriving (Eq)

-- | Validation settings:
--
-- * The set of acceptable signature algorithms
-- * The validation policy
--
data ValidationSettings = ValidationSettings
  (S.Set Alg)
  ValidationPolicy

class HasValidationSettings a where
  validationSettings :: Lens' a ValidationSettings

  validationSettingsAlgorithms :: Lens' a (S.Set Alg)
  validationSettingsAlgorithms = validationSettings . go where
    go f (ValidationSettings algs pol) =
      (\algs' -> ValidationSettings algs' pol) <$> f algs

  validationSettingsValidationPolicy :: Lens' a ValidationPolicy
  validationSettingsValidationPolicy = validationSettings . go where
    go f (ValidationSettings algs pol) =
      (\pol' -> ValidationSettings algs pol') <$> f pol

instance HasValidationSettings ValidationSettings where
  validationSettings = id

class HasAlgorithms s where
  algorithms :: Lens' s (S.Set Alg)
class HasValidationPolicy s where
  validationPolicy :: Lens' s ValidationPolicy

instance HasValidationSettings a => HasAlgorithms a where
  algorithms = validationSettingsAlgorithms
instance HasValidationSettings a => HasValidationPolicy a where
  validationPolicy = validationSettingsValidationPolicy

-- | The default validation settings.
--
-- - All algorithms except "none" are acceptable.
-- - All signatures must be valid (and there must be at least one signature.)
--
defaultValidationSettings :: ValidationSettings
defaultValidationSettings = ValidationSettings
  ( S.fromList
    [ HS256, HS384, HS512
    , RS256, RS384, RS512
    , ES256, ES384, ES512
    , PS256, PS384, PS512
    , EdDSA
    ] )
  AllValidated

-- | Verify a JWS with the default validation settings.
--
-- See also 'defaultValidationSettings'.
--
verifyJWS'
  ::  ( AsError e, MonadError e m , HasJWSHeader h, HasParams h , JWKStore k
      , Cons s s Word8 Word8, AsEmpty s
      , Foldable t
      )
  => k      -- ^ key or key store
  -> JWS t h  -- ^ JWS
  -> m s
verifyJWS' = verifyJWS defaultValidationSettings

-- | Verify a JWS.
--
-- Signatures made with an unsupported algorithms are ignored.
-- If the validation policy is 'AnyValidated', a single successfully
-- validated signature is sufficient.  If the validation policy is
-- 'AllValidated' then all remaining signatures (there must be at least one)
-- must be valid.
--
-- Returns the payload if successfully verified.
--
verifyJWS
  ::  ( HasAlgorithms a, HasValidationPolicy a, AsError e, MonadError e m
      , HasJWSHeader h, HasParams h
      , JWKStore k
      , Cons s s Word8 Word8, AsEmpty s
      , Foldable t
      )
  => a        -- ^ validation settings
  -> k        -- ^ key or key store
  -> JWS t h  -- ^ JWS
  -> m s
verifyJWS conf k (JWS p@(Types.Base64Octets p') sigs) =
  let
    algs :: S.Set Alg
    algs = conf ^. algorithms
    policy :: ValidationPolicy
    policy = conf ^. validationPolicy
    shouldValidateSig = (`elem` algs) . view (header . alg . param)
    out = view recons p'
    applyPolicy AnyValidated xs =
      if or xs then pure out else throwError (review _JWSNoValidSignatures ())
    applyPolicy AllValidated [] = throwError (review _JWSNoSignatures ())
    applyPolicy AllValidated xs =
      if and xs then pure out else throwError (review _JWSInvalidSignature ())
    validate s =
      let h = view header s
      in anyOf (keysFor Verify h) ((== Right True) . verifySig p s) k
  in
    applyPolicy policy $ map validate $ filter shouldValidateSig $ toList sigs

verifySig
  :: (HasJWSHeader a, HasParams a)
  => Types.Base64Octets
  -> Signature a
  -> JWK
  -> Either Error Bool
verifySig (Types.Base64Octets m) (Signature raw h (Types.Base64Octets s)) k =
  verify (view (alg . param) h) (view jwkMaterial k) tbs s
  where
  tbs = signingInput (maybe (Right h) Left raw) m
