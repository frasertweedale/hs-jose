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

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE MonoLocalBinds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-|

JSON Web Token implementation (RFC 7519). A JWT is a JWS
with a payload of /claims/ to be transferred between two
parties.

JWTs use the JWS /compact serialisation/.
See "Crypto.JOSE.Compact" for details.

-}
module Crypto.JWT
  (
  -- * Overview / HOWTO
  -- ** Basic usage
  -- $basic

  -- ** Supporting additional claims via subtypes #subtypes#
  -- $subtypes

  -- * API
  -- ** Creating a JWT
    SignedJWT
  , SignedJWTWithHeader
  , signJWT
  , signClaims

  -- ** Validating a JWT and extracting claims
  , defaultJWTValidationSettings
  , verifyClaims
  , verifyJWT
  , HasAllowedSkew(..)
  , HasAudiencePredicate(..)
  , HasIssuerPredicate(..)
  , HasCheckIssuedAt(..)
  , JWTValidationSettings
  , HasJWTValidationSettings(..)

  -- *** Specifying the verification time
  , WrappedUTCTime(..)
  , verifyClaimsAt
  , verifyJWTAt

  -- ** Extracting claims without verification
  , unsafeGetJWTPayload
  , unsafeGetJWTClaimsSet

  -- ** Claims Set
  , ClaimsSet
  , emptyClaimsSet
  , HasClaimsSet(..)
  , validateClaimsSet
  -- *** Unregistered claims (__deprecated__)
  , addClaim
  , unregisteredClaims

  -- ** JWT errors
  , JWTError(..)
  , AsJWTError(..)

  -- ** Miscellaneous types
  , Audience(..)
  , StringOrURI
  , stringOrUri
  , string
  , uri
  , NumericDate(..)

  -- ** Re-exports
  , module Crypto.JOSE

  ) where

import Control.Applicative
import Control.Monad
import Control.Monad.Time (MonadTime(..))
import Data.Foldable (traverse_)
import Data.Functor.Identity
import Data.Maybe
import qualified Data.String

import Control.Lens (
  makeClassy, makeClassyPrisms, makePrisms,
  Lens', _Just, over, preview, view,
  Prism', prism', Cons, iso, AsEmpty)
import Control.Lens.Cons.Extras (recons)
import Control.Monad.Error.Lens (throwing, throwing_)
import Control.Monad.Except (MonadError)
import Control.Monad.Reader (ReaderT, asks, runReaderT)
import Data.Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.Text as T
import Data.Time (NominalDiffTime, UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime, utcTimeToPOSIXSeconds)
import Network.URI (parseURI)

import Crypto.JOSE
import Crypto.JOSE.Types

{- $basic

@
import Crypto.JWT

mkClaims :: IO 'ClaimsSet'
mkClaims = do
  t <- 'currentTime'
  pure $ 'emptyClaimsSet'
    & 'claimIss' ?~ "alice"
    & 'claimAud' ?~ 'Audience' ["bob"]
    & 'claimIat' ?~ 'NumericDate' t

doJwtSign :: 'JWK' -> 'ClaimsSet' -> IO (Either 'JWTError' 'SignedJWT')
doJwtSign jwk claims = 'runJOSE' $ do
  alg \<- 'bestJWSAlg' jwk
  'signClaims' jwk ('newJWSHeaderProtected' alg) claims

doJwtVerify :: 'JWK' -> 'SignedJWT' -> IO (Either 'JWTError' 'ClaimsSet')
doJwtVerify jwk jwt = 'runJOSE' $ do
  let config = 'defaultJWTValidationSettings' (== "bob")
  'verifyClaims' config jwk jwt
@

Some JWT libraries have a function that takes two strings: the
"secret" (a symmetric key) and the raw JWT.  The following function
achieves the same:

@
verify :: L.ByteString -> L.ByteString -> IO (Either 'JWTError' 'ClaimsSet')
verify k s = 'runJOSE' $ do
  let
    k' = 'fromOctets' k      -- turn raw secret into symmetric JWK
    audCheck = const True  -- should be a proper audience check
  jwt <- 'decodeCompact' s   -- decode JWT
  'verifyClaims' ('defaultJWTValidationSettings' audCheck) k' (jwt :: 'SignedJWT')
@

-}

{- $subtypes

For applications that use __additional claims__, define a data type that wraps
'ClaimsSet' and includes fields for the additional claims.  You will also need
to define 'FromJSON' if verifying JWTs, and 'ToJSON' if producing JWTs.  The
following example is taken from
<https://datatracker.ietf.org/doc/html/rfc7519#section-3.1 RFC 7519 §3.1>.

@
import qualified Data.Aeson.KeyMap as M

data Super = Super { jwtClaims :: 'ClaimsSet', isRoot :: Bool }

instance 'HasClaimsSet' Super where
  'claimsSet' f s = fmap (\\a' -> s { jwtClaims = a' }) (f (jwtClaims s))

instance FromJSON Super where
  parseJSON = withObject \"Super\" $ \\o -> Super
    \<$\> parseJSON (Object o)
    \<*\> o .: "http://example.com/is_root"

instance ToJSON Super where
  toJSON s =
    ins "http://example.com/is_root" (isRoot s) (toJSON (jwtClaims s))
    where
      ins k v (Object o) = Object $ M.insert k (toJSON v) o
      ins _ _ a = a
@

__Use 'signJWT' and 'verifyJWT' when using custom payload types__ (instead of
'signClaims' and 'verifyClaims' which are specialised to 'ClaimsSet').

-}


data JWTError
  = JWSError Error
  -- ^ A JOSE error occurred while processing the JWT
  | JWTClaimsSetDecodeError String
  -- ^ The JWT payload is not a JWT Claims Set
  | JWTExpired
  | JWTNotYetValid
  | JWTNotInIssuer
  | JWTNotInAudience
  | JWTIssuedAtFuture
  deriving (Eq, Show)
makeClassyPrisms ''JWTError

instance AsError JWTError where
  _Error = _JWSError


-- RFC 7519 §2.  Terminology

-- | A JSON string value, with the additional requirement that while
--   arbitrary string values MAY be used, any value containing a @:@
--   character MUST be a URI.
--
-- __Note__: the 'IsString' instance will fail if the string
-- contains a @:@ but does not parse as a 'URI'.  Use 'stringOrUri'
-- directly in this situation.
--
data StringOrURI = Arbitrary T.Text | OrURI URI deriving (Eq, Show)

-- | Non-total.  A string with a @':'@ in it MUST parse as a URI
instance Data.String.IsString StringOrURI where
  fromString = fromJust . preview stringOrUri

stringOrUri :: (Cons s s Char Char, AsEmpty s) => Prism' s StringOrURI
stringOrUri = iso (view recons) (view recons) . prism' rev fwd
  where
  rev (Arbitrary s) = s
  rev (OrURI x) = T.pack (show x)
  fwd s
    | T.any (== ':') s = OrURI <$> parseURI (T.unpack s)
    | otherwise = pure (Arbitrary s)
{-# INLINE stringOrUri #-}

string :: Prism' StringOrURI T.Text
string = prism' Arbitrary f where
  f (Arbitrary s) = Just s
  f _ = Nothing

uri :: Prism' StringOrURI URI
uri = prism' OrURI f where
  f (OrURI s) = Just s
  f _ = Nothing

instance FromJSON StringOrURI where
  parseJSON = withText "StringOrURI"
    (maybe (fail "failed to parse StringOrURI") pure . preview stringOrUri)

instance ToJSON StringOrURI where
  toJSON (Arbitrary s)  = toJSON s
  toJSON (OrURI x)      = toJSON $ show x


-- | A JSON numeric value representing the number of seconds from
--   1970-01-01T0:0:0Z UTC until the specified UTC date\/time.
--
newtype NumericDate = NumericDate UTCTime deriving (Eq, Ord, Show)
makePrisms ''NumericDate

instance FromJSON NumericDate where
  parseJSON = withScientific "NumericDate" $
    pure . NumericDate . posixSecondsToUTCTime . fromRational . toRational

instance ToJSON NumericDate where
  toJSON (NumericDate t)
    = Number $ fromRational $ toRational $ utcTimeToPOSIXSeconds t


-- | Audience data.  In the general case, the /aud/ value is an
-- array of case-sensitive strings, each containing a 'StringOrURI'
-- value.  In the special case when the JWT has one audience, the
-- /aud/ value MAY be a single case-sensitive string containing a
-- 'StringOrURI' value.
--
-- The 'ToJSON' instance formats an 'Audience' with one value as a
-- string (some non-compliant implementations require this.)
--
newtype Audience = Audience [StringOrURI] deriving (Eq, Show)
makePrisms ''Audience

instance FromJSON Audience where
  parseJSON v = Audience <$> (parseJSON v <|> fmap (:[]) (parseJSON v))

instance ToJSON Audience where
  toJSON (Audience [aud]) = toJSON aud
  toJSON (Audience auds) = toJSON auds


-- | The JWT Claims Set represents a JSON object whose members are
-- the registered claims defined by RFC 7519.  To construct a
-- @ClaimsSet@ use 'emptyClaimsSet' then use the lenses defined in
-- 'HasClaimsSet' to set relevant claims.
--
-- For applications that use additional claims beyond those defined
-- by RFC 7519, define a [subtype](#g:subtypes) and instance 'HasClaimsSet'.
--
data ClaimsSet = ClaimsSet
  { _claimIss :: Maybe StringOrURI
  , _claimSub :: Maybe StringOrURI
  , _claimAud :: Maybe Audience
  , _claimExp :: Maybe NumericDate
  , _claimNbf :: Maybe NumericDate
  , _claimIat :: Maybe NumericDate
  , _claimJti :: Maybe T.Text
  , _unregisteredClaims :: M.Map T.Text Value
  }
  deriving (Eq, Show)

class HasClaimsSet a where
  claimsSet :: Lens' a ClaimsSet

  -- | The issuer claim identifies the principal that issued the
  -- JWT.  The processing of this claim is generally application
  -- specific.
  claimIss :: Lens' a (Maybe StringOrURI)
  {-# INLINE claimIss #-}

  -- | The subject claim identifies the principal that is the
  -- subject of the JWT.  The Claims in a JWT are normally
  -- statements about the subject.  The subject value MAY be scoped
  -- to be locally unique in the context of the issuer or MAY be
  -- globally unique.  The processing of this claim is generally
  -- application specific.
  claimSub :: Lens' a (Maybe StringOrURI)
  {-# INLINE claimSub #-}

  -- | The audience claim identifies the recipients that the JWT is
  -- intended for.  Each principal intended to process the JWT MUST
  -- identify itself with a value in the audience claim.  If the
  -- principal processing the claim does not identify itself with a
  -- value in the /aud/ claim when this claim is present, then the
  -- JWT MUST be rejected.
  claimAud :: Lens' a (Maybe Audience)
  {-# INLINE claimAud #-}

  -- | The expiration time claim identifies the expiration time on
  -- or after which the JWT MUST NOT be accepted for processing.
  -- The processing of /exp/ claim requires that the current
  -- date\/time MUST be before expiration date\/time listed in the
  -- /exp/ claim.  Implementers MAY provide for some small leeway,
  -- usually no more than a few minutes, to account for clock skew.
  claimExp :: Lens' a (Maybe NumericDate)
  {-# INLINE claimExp #-}

  -- | The not before claim identifies the time before which the JWT
  -- MUST NOT be accepted for processing.  The processing of the
  -- /nbf/ claim requires that the current date\/time MUST be after
  -- or equal to the not-before date\/time listed in the /nbf/
  -- claim.  Implementers MAY provide for some small leeway, usually
  -- no more than a few minutes, to account for clock skew.
  claimNbf :: Lens' a (Maybe NumericDate)
  {-# INLINE claimNbf #-}

  -- | The issued at claim identifies the time at which the JWT was
  -- issued.  This claim can be used to determine the age of the
  -- JWT.
  claimIat :: Lens' a (Maybe NumericDate)
  {-# INLINE claimIat #-}

  -- | The JWT ID claim provides a unique identifier for the JWT.
  -- The identifier value MUST be assigned in a manner that ensures
  -- that there is a negligible probability that the same value will
  -- be accidentally assigned to a different data object.  The /jti/
  -- claim can be used to prevent the JWT from being replayed.  The
  -- /jti/ value is a case-sensitive string.
  claimJti :: Lens' a (Maybe T.Text)
  {-# INLINE claimJti #-}

  claimAud = claimsSet . claimAud
  claimExp = claimsSet . claimExp
  claimIat = claimsSet . claimIat
  claimIss = claimsSet . claimIss
  claimJti = claimsSet . claimJti
  claimNbf = claimsSet . claimNbf
  claimSub = claimsSet . claimSub

instance HasClaimsSet ClaimsSet where
  claimsSet = id

  claimIss f h@ClaimsSet{ _claimIss = a} = fmap (\a' -> h { _claimIss = a' }) (f a)
  {-# INLINE claimIss #-}

  claimSub f h@ClaimsSet{ _claimSub = a} = fmap (\a' -> h { _claimSub = a' }) (f a)
  {-# INLINE claimSub #-}

  claimAud f h@ClaimsSet{ _claimAud = a} = fmap (\a' -> h { _claimAud = a' }) (f a)
  {-# INLINE claimAud #-}

  claimExp f h@ClaimsSet{ _claimExp = a} = fmap (\a' -> h { _claimExp = a' }) (f a)
  {-# INLINE claimExp #-}

  claimNbf f h@ClaimsSet{ _claimNbf = a} = fmap (\a' -> h { _claimNbf = a' }) (f a)
  {-# INLINE claimNbf #-}

  claimIat f h@ClaimsSet{ _claimIat = a} = fmap (\a' -> h { _claimIat = a' }) (f a)
  {-# INLINE claimIat #-}

  claimJti f h@ClaimsSet{ _claimJti = a} = fmap (\a' -> h { _claimJti = a' }) (f a)
  {-# INLINE claimJti #-}

-- | Claim Names can be defined at will by those using JWTs.
-- Use this lens to access a map non-RFC 7519 claims in the
-- Claims Set object.
unregisteredClaims :: Lens' ClaimsSet (M.Map T.Text Value)
unregisteredClaims f h@ClaimsSet{ _unregisteredClaims = a} =
  fmap (\a' -> h { _unregisteredClaims = a' }) (f a)
{-# INLINE unregisteredClaims #-}
{-# DEPRECATED unregisteredClaims "use a [subtype](#g:subtypes) to define additional claims" #-}

-- | Return an empty claims set.
--
emptyClaimsSet :: ClaimsSet
emptyClaimsSet = ClaimsSet n n n n n n n M.empty where n = Nothing

-- | Add a __non-RFC 7519__ claim.  Use the lenses from the
-- 'HasClaimsSet' class for setting registered claims.
--
addClaim :: T.Text -> Value -> ClaimsSet -> ClaimsSet
addClaim k v = over unregisteredClaims (M.insert k v)
{-# DEPRECATED addClaim "use a [subtype](#g:subtypes) to define additional claims" #-}

registeredClaims :: S.Set T.Text
registeredClaims = S.fromDistinctAscList
  [ "aud"
  , "exp"
  , "iat"
  , "iss"
  , "jti"
  , "nbf"
  , "sub"
  ]

filterUnregistered :: M.Map T.Text Value -> M.Map T.Text Value
filterUnregistered m =
  m `M.withoutKeys` registeredClaims

toKeyMap :: M.Map T.Text Value -> KeyMap.KeyMap Value
toKeyMap = KeyMap.fromMap . M.mapKeysMonotonic Key.fromText

fromKeyMap :: KeyMap.KeyMap Value -> M.Map T.Text Value
fromKeyMap = M.mapKeysMonotonic Key.toText . KeyMap.toMap

instance FromJSON ClaimsSet where
  parseJSON = withObject "JWT Claims Set" (\o -> ClaimsSet
    <$> o .:? "iss"
    <*> o .:? "sub"
    <*> o .:? "aud"
    <*> o .:? "exp"
    <*> o .:? "nbf"
    <*> o .:? "iat"
    <*> o .:? "jti"
    <*> pure (filterUnregistered . fromKeyMap $ o)
    )

instance ToJSON ClaimsSet where
  toJSON (ClaimsSet iss sub aud exp' nbf iat jti o) = Object $
    ( KeyMap.fromMap . M.fromDistinctAscList $ catMaybes
      [ fmap ("aud" .=) aud
      , fmap ("exp" .=) exp'
      , fmap ("iat" .=) iat
      , fmap ("iss" .=) iss
      , fmap ("jti" .=) jti
      , fmap ("nbf" .=) nbf
      , fmap ("sub" .=) sub
      ]
    )
    <> toKeyMap (filterUnregistered o)


data JWTValidationSettings = JWTValidationSettings
  { _jwtValidationSettingsValidationSettings :: ValidationSettings
  , _jwtValidationSettingsAllowedSkew :: NominalDiffTime
  , _jwtValidationSettingsCheckIssuedAt :: Bool
  -- ^ The allowed skew is interpreted in absolute terms;
  --   a nonzero value always expands the validity period.
  , _jwtValidationSettingsAudiencePredicate :: StringOrURI -> Bool
  , _jwtValidationSettingsIssuerPredicate :: StringOrURI -> Bool
  }
makeClassy ''JWTValidationSettings

instance {-# OVERLAPPABLE #-} HasJWTValidationSettings a => HasValidationSettings a where
  validationSettings = jwtValidationSettingsValidationSettings

-- | Maximum allowed skew when validating the /nbf/, /exp/ and /iat/ claims.
class HasAllowedSkew s where
  allowedSkew :: Lens' s NominalDiffTime

-- | Predicate for checking values in the /aud/ claim.
class HasAudiencePredicate s where
  audiencePredicate :: Lens' s (StringOrURI -> Bool)

-- | Predicate for checking the /iss/ claim.
class HasIssuerPredicate s where
  issuerPredicate :: Lens' s (StringOrURI -> Bool)

-- | Whether to check that the /iat/ claim is not in the future.
class HasCheckIssuedAt s where
  checkIssuedAt :: Lens' s Bool

instance HasJWTValidationSettings a => HasAllowedSkew a where
  allowedSkew = jwtValidationSettingsAllowedSkew
instance HasJWTValidationSettings a => HasAudiencePredicate a where
  audiencePredicate = jwtValidationSettingsAudiencePredicate
instance HasJWTValidationSettings a => HasIssuerPredicate a where
  issuerPredicate = jwtValidationSettingsIssuerPredicate
instance HasJWTValidationSettings a => HasCheckIssuedAt a where
  checkIssuedAt = jwtValidationSettingsCheckIssuedAt

-- | Acquire the default validation settings.
--
-- <https://tools.ietf.org/html/rfc7519#section-4.1.3 RFC 7519 §4.1.3.>
-- states that applications MUST identify itself with a value in the
-- audience claim, therefore a predicate must be supplied.
--
-- The other defaults are:
--
-- - 'defaultValidationSettings' for JWS verification
-- - Zero clock skew tolerance when validating /nbf/, /exp/ and /iat/ claims
-- - /iat/ claim is checked
-- - /issuer/ claim is not checked
--
defaultJWTValidationSettings :: (StringOrURI -> Bool) -> JWTValidationSettings
defaultJWTValidationSettings p = JWTValidationSettings
  defaultValidationSettings
  0
  True
  p
  (const True)

-- | Validate the claims made by a ClaimsSet.
--
-- __You should never need to use this function directly.__
-- These checks are always performed by 'verifyClaims' and 'verifyJWT'.
-- The function is exported mainly for testing purposes.
--
validateClaimsSet
  ::
    ( MonadTime m, HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , AsJWTError e, MonadError e m
    )
  => a
  -> ClaimsSet
  -> m ClaimsSet
validateClaimsSet conf claims =
  claims <$ traverse_ (($ claims) . ($ conf))
    [ validateExpClaim
    , validateIatClaim
    , validateNbfClaim
    , validateIssClaim
    , validateAudClaim
    ]

validateExpClaim
  :: (MonadTime m, HasAllowedSkew a, AsJWTError e, MonadError e m)
  => a
  -> ClaimsSet
  -> m ()
validateExpClaim conf =
  traverse_ (\t -> do
    now <- currentTime
    unless (now < addUTCTime (abs (view allowedSkew conf)) (view _NumericDate t)) $
      throwing_ _JWTExpired )
  . preview (claimExp . _Just)

validateIatClaim
  :: (MonadTime m, HasCheckIssuedAt a, HasAllowedSkew a, AsJWTError e, MonadError e m)
  => a
  -> ClaimsSet
  -> m ()
validateIatClaim conf =
  traverse_ (\t -> do
    now <- currentTime
    when (view checkIssuedAt conf) $
      when (view _NumericDate t > addUTCTime (abs (view allowedSkew conf)) now) $
        throwing_ _JWTIssuedAtFuture )
    . preview (claimIat . _Just)

validateNbfClaim
  :: (MonadTime m, HasAllowedSkew a, AsJWTError e, MonadError e m)
  => a
  -> ClaimsSet
  -> m ()
validateNbfClaim conf =
  traverse_ (\t -> do
    now <- currentTime
    unless (now >= addUTCTime (negate (abs (view allowedSkew conf))) (view _NumericDate t)) $
      throwing_ _JWTNotYetValid )
  . preview (claimNbf . _Just)

validateAudClaim
  :: (HasAudiencePredicate s, AsJWTError e, MonadError e m)
  => s
  -> ClaimsSet
  -> m ()
validateAudClaim conf =
  traverse_
    (\auds -> unless (or (view audiencePredicate conf <$> auds)) $
        throwing_ _JWTNotInAudience )
  . preview (claimAud . _Just . _Audience)

validateIssClaim
  :: (HasIssuerPredicate s, AsJWTError e, MonadError e m)
  => s
  -> ClaimsSet
  -> m ()
validateIssClaim conf =
  traverse_ (\iss ->
    unless (view issuerPredicate conf iss) (throwing_ _JWTNotInIssuer) )
  . preview (claimIss . _Just)

-- | A digitally signed or MAC'd JWT, with the JWS header type fixed
-- at 'JWSHeader'.
--
type SignedJWT = SignedJWTWithHeader JWSHeader

-- | A digitally signed or MAC'd JWT, with caller-specified JWS
-- header type.  For information about defining custom header types
-- see /Defining additional header parameters/ in "Crypto.JOSE.JWS".
--
type SignedJWTWithHeader h = CompactJWS h

newtype WrappedUTCTime = WrappedUTCTime { getUTCTime :: UTCTime }

-- | @'monotonicTime' = pure 0@.  /jose/ doesn't use this so we fake it
instance Monad m => MonadTime (ReaderT WrappedUTCTime m) where
  currentTime = asks getUTCTime
  monotonicTime = pure 0

-- | Get the JWT payload __without verifying it__.  Do not use this
-- function unless you have a compelling reason.
--
-- Most applications should use 'verifyJWT' or one of its variants
-- to verify the JWT and access the claims.
--
-- See also 'unsafeGetJWTClaimsSet' which is the same as this
-- function with the payload type specialised to 'ClaimsSet'.
--
unsafeGetJWTPayload
  :: ( FromJSON payload, AsJWTError e, MonadError e m )
  => SignedJWT -> m payload
unsafeGetJWTPayload = unsafeGetPayload f
  where
  f = either (throwing _JWTClaimsSetDecodeError) pure . eitherDecode

-- | Variant of 'unsafeGetJWTPayload' specialised to 'ClaimsSet'
unsafeGetJWTClaimsSet
  :: ( AsJWTError e, MonadError e m )
  => SignedJWT -> m ClaimsSet
unsafeGetJWTClaimsSet = unsafeGetJWTPayload


-- | Cryptographically verify a JWS JWT, then validate the
-- Claims Set, returning it if valid.  The claims are validated
-- at the current system time.
--
-- This function is abstracted over any payload type with 'HasClaimsSet' and
-- 'FromJSON' instances.  The 'verifyClaims' variant uses 'ClaimsSet' as the
-- payload type.
--
-- See also 'verifyClaimsAt' which allows you to explicitly specify
-- the time of validation (against which time-related claims will be
-- validated).
--
verifyJWT
  ::
    ( MonadTime m, HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , HasValidationSettings a
    , HasJWSHeader h, HasParams h
    , AsError e, AsJWTError e, MonadError e m
    , VerificationKeyStore m (h RequiredProtection) payload k
    , HasClaimsSet payload, FromJSON payload
    )
  => a
  -- ^ Validation settings
  -> k
  -- ^ Key store
  -> SignedJWTWithHeader h
  -- ^ JWT.  Simple use cases may find the 'SignedJWT' type synonym useful for
  -- fixing the type of @h@.
  -> m payload
verifyJWT conf k jws =
  -- It is important, for security reasons, that the signature get
  -- verified before the claims.
  verifyJWSWithPayload f conf k jws >>= claimsSet (validateClaimsSet conf)
  where
    f = either (throwing _JWTClaimsSetDecodeError) pure . eitherDecode

-- | Variant of 'verifyJWT' that uses 'ClaimsSet' as the payload type.
--
verifyClaims
  ::
    ( MonadTime m, HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , HasValidationSettings a
    , HasJWSHeader h, HasParams h
    , AsError e, AsJWTError e, MonadError e m
    , VerificationKeyStore m (h RequiredProtection) ClaimsSet k
    )
  => a
  -- ^ Validation settings
  -> k
  -- ^ Key store
  -> SignedJWTWithHeader h
  -- ^ JWT.  Simple use cases may find the 'SignedJWT' type synonym useful for
  -- fixing the type of @h@.
  -> m ClaimsSet
verifyClaims = verifyJWT

-- | Variant of 'verifyJWT' where the validation time is provided by
-- caller.  If you process many tokens per second
-- this lets you avoid unnecessary repeat system calls.
--
verifyJWTAt
  ::
    ( HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , HasValidationSettings a
    , HasJWSHeader h, HasParams h
    , AsError e, AsJWTError e, MonadError e m
    , VerificationKeyStore (ReaderT WrappedUTCTime m) (h RequiredProtection) payload k
    , HasClaimsSet payload, FromJSON payload
    )
  => a
  -- ^ Validation settings
  -> k
  -- ^ Key store
  -> UTCTime
  -- ^ Validation time
  -> SignedJWTWithHeader h
  -- ^ JWT.  Simple use cases may find the 'SignedJWT' type synonym useful for
  -- fixing the type of @h@.
  -> m payload
verifyJWTAt a k t jwt = runReaderT (verifyJWT a k jwt) (WrappedUTCTime t)

-- | Variant of 'verifyJWT' that uses 'ClaimsSet' as the payload type and
-- where validation time is provided by caller.
--
verifyClaimsAt
  ::
    ( HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , HasValidationSettings a
    , HasJWSHeader h, HasParams h
    , AsError e, AsJWTError e, MonadError e m
    , VerificationKeyStore (ReaderT WrappedUTCTime m) (h RequiredProtection) ClaimsSet k
    )
  => a
  -- ^ Validation settings
  -> k
  -- ^ Key store
  -> UTCTime
  -- ^ Validation time
  -> SignedJWTWithHeader h
  -- ^ JWT.  Simple use cases may find the 'SignedJWT' type synonym useful for
  -- fixing the type of @h@.
  -> m ClaimsSet
verifyClaimsAt = verifyJWTAt


-- | Create a JWS JWT.  The payload can be any type with a 'ToJSON'
-- instance.  See also 'signClaims' which uses 'ClaimsSet' as the
-- payload type.
--
-- __Does not set any fields in the Claims Set__, such as @"iat"@
-- ("Issued At") Claim.  The payload is encoded as-is.
--
signJWT
  :: ( MonadRandom m, MonadError e m, AsError e
     , HasJWSHeader h, HasParams h
     , ToJSON payload )
  => JWK
  -- ^ Signing key
  -> h RequiredProtection
  -- ^ JWS Header.  Commonly this will be 'JWSHeader'.  If your application
  -- uses additional header fields, see /Defining additional header parameters/
  -- in "Crypto.JOSE.JWS".
  -> payload
  -- ^ The payload ('ClaimsSet' or a subtype).
  -> m (SignedJWTWithHeader h)
signJWT k h c = signJWS (encode c) (Identity (h, k))

-- | Create a JWS JWT.  Specialisation of 'signJWT' with payload type fixed
-- at 'ClaimsSet'.
--
-- __Does not set any fields in the Claims Set__, such as @"iat"@
-- ("Issued At") Claim.  The payload is encoded as-is.
--
signClaims
  :: ( MonadRandom m, MonadError e m, AsError e
     , HasJWSHeader h, HasParams h )
  => JWK
  -- ^ Signing key
  -> h RequiredProtection
  -- ^ JWS Header.  Commonly this will be 'JWSHeader'.  If your application
  -- uses additional header fields, see /Defining additional header parameters/
  -- in "Crypto.JOSE.JWS".
  -> ClaimsSet
  -- ^ Payload
  -> m (SignedJWTWithHeader h)
signClaims = signJWT
