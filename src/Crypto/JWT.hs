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

{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE UndecidableInstances #-}

{-|

JSON Web Token implementation (RFC 7519). A JWT is a JWS
with a payload of /claims/ to be transferred between two
parties.

JWTs use the JWS /compact serialisation/.
See "Crypto.JOSE.Compact" for details.

@
mkClaims :: IO 'ClaimsSet'
mkClaims = do
  t <- 'currentTime'
  pure $ 'emptyClaimsSet'
    & 'claimIss' .~ Just ("alice")
    & 'claimAud' .~ Just ('Audience' ["bob"])
    & 'claimIat' .~ Just ('NumericDate' t)

doJwtSign :: 'JWK' -> 'ClaimsSet' -> IO (Either 'JWTError' 'SignedJWT')
doJwtSign jwk claims = runExceptT $ do
  alg \<- 'bestJWSAlg' jwk
  'signClaims' jwk ('newJWSHeader' ((), alg)) claims

doJwtVerify :: 'JWK' -> 'SignedJWT' -> IO (Either 'JWTError' 'ClaimsSet')
doJwtVerify jwk jwt = runExceptT $ do
  let config = 'defaultJWTValidationSettings' (== "bob")
  'verifyClaims' config jwk jwt
@

-}
module Crypto.JWT
  (
  -- * Creating a JWT
    signClaims
  , JWT
  , SignedJWT

  -- * Validating a JWT and extracting claims
  , defaultJWTValidationSettings
  , verifyClaims
  , verifyClaimsAt
  , HasAllowedSkew(..)
  , HasAudiencePredicate(..)
  , HasIssuerPredicate(..)
  , HasCheckIssuedAt(..)
  , JWTValidationSettings
  , HasJWTValidationSettings(..)

  -- * Claims Set
  , ClaimsSet
  , claimAud
  , claimExp
  , claimIat
  , claimIss
  , claimJti
  , claimNbf
  , claimSub
  , unregisteredClaims
  , addClaim
  , emptyClaimsSet
  , validateClaimsSet

  -- * JWT errors
  , JWTError(..)
  , AsJWTError(..)

  -- * Miscellaneous
  , Audience(..)
  , StringOrURI
  , stringOrUri
  , string
  , uri
  , NumericDate(..)

  , module Crypto.JOSE

  ) where

import Control.Applicative
import Control.Monad
import Control.Monad.Time (MonadTime(..))
#if ! MIN_VERSION_monad_time(0,2,0)
import Control.Monad.Time.Instances ()
#endif
import Data.Foldable (traverse_)
import Data.Functor.Identity
import Data.Maybe
import Data.List (unfoldr)
import qualified Data.String

import Control.Lens (
  makeClassy, makeClassyPrisms, makePrisms,
  Lens', _Just, over, preview, review, view,
  Prism', prism', Cons, cons, uncons, iso, Iso')
import Control.Monad.Except (MonadError(throwError))
import Control.Monad.Reader (ReaderT, ask, runReaderT)
import Data.Aeson
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Data.Time (NominalDiffTime, UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime, utcTimeToPOSIXSeconds)
import Network.URI (parseURI)

import Crypto.JOSE
import Crypto.JOSE.Types


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
data StringOrURI = Arbitrary String | OrURI URI deriving (Eq, Show)

instance Data.String.IsString StringOrURI where
  fromString = fromJust . preview stringOrUri

consString :: (Cons s s Char Char, Monoid s) => Iso' s String
consString = iso (unfoldr uncons) (foldr cons mempty)

stringOrUri :: (Cons s s Char Char, Monoid s) => Prism' s StringOrURI
stringOrUri = consString . prism' rev fwd
  where
  rev (Arbitrary s) = s
  rev (OrURI x) = show x
  fwd s = if ':' `elem` s then OrURI <$> parseURI s else pure (Arbitrary s)

string :: Prism' StringOrURI String
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
-- the registered claims defined by RFC 7519.  Unrecognised
-- claims are gathered into the 'unregisteredClaims' map.
--
data ClaimsSet = ClaimsSet
  { _claimIss :: Maybe StringOrURI
  , _claimSub :: Maybe StringOrURI
  , _claimAud :: Maybe Audience
  , _claimExp :: Maybe NumericDate
  , _claimNbf :: Maybe NumericDate
  , _claimIat :: Maybe NumericDate
  , _claimJti :: Maybe T.Text
  , _unregisteredClaims :: M.HashMap T.Text Value
  }
  deriving (Eq, Show)

-- | The issuer claim identifies the principal that issued the
-- JWT.  The processing of this claim is generally application
-- specific.
claimIss :: Lens' ClaimsSet (Maybe StringOrURI)
claimIss f h@(ClaimsSet { _claimIss = a}) =
  fmap (\a' -> h { _claimIss = a' }) (f a)

-- | The subject claim identifies the principal that is the
-- subject of the JWT.  The Claims in a JWT are normally
-- statements about the subject.  The subject value MAY be scoped
-- to be locally unique in the context of the issuer or MAY be
-- globally unique.  The processing of this claim is generally
-- application specific.
claimSub :: Lens' ClaimsSet (Maybe StringOrURI)
claimSub f h@(ClaimsSet { _claimSub = a}) =
  fmap (\a' -> h { _claimSub = a' }) (f a)

-- | The audience claim identifies the recipients that the JWT is
-- intended for.  Each principal intended to process the JWT MUST
-- identify itself with a value in the audience claim.  If the
-- principal processing the claim does not identify itself with a
-- value in the /aud/ claim when this claim is present, then the
-- JWT MUST be rejected.
claimAud :: Lens' ClaimsSet (Maybe Audience)
claimAud f h@(ClaimsSet { _claimAud = a}) =
  fmap (\a' -> h { _claimAud = a' }) (f a)

-- | The expiration time claim identifies the expiration time on
-- or after which the JWT MUST NOT be accepted for processing.
-- The processing of /exp/ claim requires that the current
-- date\/time MUST be before expiration date\/time listed in the
-- /exp/ claim.  Implementers MAY provide for some small leeway,
-- usually no more than a few minutes, to account for clock skew.
claimExp :: Lens' ClaimsSet (Maybe NumericDate)
claimExp f h@(ClaimsSet { _claimExp = a}) =
  fmap (\a' -> h { _claimExp = a' }) (f a)

-- | The not before claim identifies the time before which the JWT
-- MUST NOT be accepted for processing.  The processing of the
-- /nbf/ claim requires that the current date\/time MUST be after
-- or equal to the not-before date\/time listed in the /nbf/
-- claim.  Implementers MAY provide for some small leeway, usually
-- no more than a few minutes, to account for clock skew.
claimNbf :: Lens' ClaimsSet (Maybe NumericDate)
claimNbf f h@(ClaimsSet { _claimNbf = a}) =
  fmap (\a' -> h { _claimNbf = a' }) (f a)

-- | The issued at claim identifies the time at which the JWT was
-- issued.  This claim can be used to determine the age of the
-- JWT.
claimIat :: Lens' ClaimsSet (Maybe NumericDate)
claimIat f h@(ClaimsSet { _claimIat = a}) =
  fmap (\a' -> h { _claimIat = a' }) (f a)

-- | The JWT ID claim provides a unique identifier for the JWT.
-- The identifier value MUST be assigned in a manner that ensures
-- that there is a negligible probability that the same value will
-- be accidentally assigned to a different data object.  The /jti/
-- claim can be used to prevent the JWT from being replayed.  The
-- /jti/ value is a case-sensitive string.
claimJti :: Lens' ClaimsSet (Maybe T.Text)
claimJti f h@(ClaimsSet { _claimJti = a}) =
  fmap (\a' -> h { _claimJti = a' }) (f a)

-- | Claim Names can be defined at will by those using JWTs.
unregisteredClaims :: Lens' ClaimsSet (M.HashMap T.Text Value)
unregisteredClaims f h@(ClaimsSet { _unregisteredClaims = a}) =
  fmap (\a' -> h { _unregisteredClaims = a' }) (f a)


-- | Return an empty claims set.
--
emptyClaimsSet :: ClaimsSet
emptyClaimsSet = ClaimsSet n n n n n n n M.empty where n = Nothing

addClaim :: T.Text -> Value -> ClaimsSet -> ClaimsSet
addClaim k v = over unregisteredClaims (M.insert k v)

filterUnregistered :: M.HashMap T.Text Value -> M.HashMap T.Text Value
filterUnregistered = M.filterWithKey (\k _ -> k `notElem` registered) where
  registered = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

instance FromJSON ClaimsSet where
  parseJSON = withObject "JWT Claims Set" (\o -> ClaimsSet
    <$> o .:? "iss"
    <*> o .:? "sub"
    <*> o .:? "aud"
    <*> o .:? "exp"
    <*> o .:? "nbf"
    <*> o .:? "iat"
    <*> o .:? "jti"
    <*> pure (filterUnregistered o))

instance ToJSON ClaimsSet where
  toJSON (ClaimsSet iss sub aud exp' nbf iat jti o) = object $ catMaybes [
    fmap ("iss" .=) iss
    , fmap ("sub" .=) sub
    , fmap ("aud" .=) aud
    , fmap ("exp" .=) exp'
    , fmap ("nbf" .=) nbf
    , fmap ("iat" .=) iat
    , fmap ("jti" .=) jti
    ] ++ M.toList (filterUnregistered o)


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

instance HasValidationSettings JWTValidationSettings where
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
-- These checks are performed by 'verifyClaims', which also
-- validates any signatures, so you shouldn't need to use this
-- function directly.
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
  traverse_ (($ claims) . ($ conf))
    [ validateExpClaim
    , validateIatClaim
    , validateNbfClaim
    , validateIssClaim
    , validateAudClaim
    ]
  *> pure claims

validateExpClaim
  :: (MonadTime m, HasAllowedSkew a, AsJWTError e, MonadError e m)
  => a
  -> ClaimsSet
  -> m ()
validateExpClaim conf =
  traverse_ (\t -> do
    now <- currentTime
    unless (now < addUTCTime (abs (view allowedSkew conf)) (view _NumericDate t)) $
      throwError (review _JWTExpired ()))
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
      when ((view _NumericDate t) > addUTCTime (abs (view allowedSkew conf)) now) $
        throwError (review _JWTIssuedAtFuture ()))
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
      throwError (review _JWTNotYetValid ()))
  . preview (claimNbf . _Just)

validateAudClaim
  :: (HasAudiencePredicate s, AsJWTError e, MonadError e m)
  => s
  -> ClaimsSet
  -> m ()
validateAudClaim conf =
  traverse_
    (\auds -> unless (or (view audiencePredicate conf <$> auds)) $
        throwError (review _JWTNotInAudience ()))
  . preview (claimAud . _Just . _Audience)

validateIssClaim
  :: (HasIssuerPredicate s, AsJWTError e, MonadError e m)
  => s
  -> ClaimsSet
  -> m ()
validateIssClaim conf =
  traverse_ (\iss ->
    unless (view issuerPredicate conf iss) $
      throwError (review _JWTNotInIssuer ()))
  . preview (claimIss . _Just)


-- | JSON Web Token data.
--
newtype JWT a = JWT a
  deriving (Eq, Show)

-- | A digitally signed or MACed JWT
--
type SignedJWT = JWT (CompactJWS JWSHeader)

instance FromCompact a => FromCompact (JWT a) where
  fromCompact = fmap JWT . fromCompact

instance ToCompact a => ToCompact (JWT a) where
  toCompact (JWT a) = toCompact a


newtype WrappedUTCTime = WrappedUTCTime { getUTCTime :: UTCTime }

instance Monad m => MonadTime (ReaderT WrappedUTCTime m) where
  currentTime = getUTCTime <$> ask


-- | Cryptographically verify a JWS JWT, then validate the
-- Claims Set, returning it if valid.
--
-- This is the only way to get at the claims of a JWS JWT,
-- enforcing that the claims are cryptographically and
-- semantically valid before the application can use them.
--
-- See also 'verifyClaimsAt' which allows you to explicitly specify
-- the time.
--
verifyClaims
  ::
    ( MonadTime m, HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , HasValidationSettings a
    , AsError e, AsJWTError e, MonadError e m
    , JWKStore k
    )
  => a
  -> k
  -> SignedJWT
  -> m ClaimsSet
verifyClaims conf k (JWT jws) =
  -- It is important, for security reasons, that the signature get
  -- verified before the claims.
  verifyJWS conf k jws
  >>= either (throwError . review _JWTClaimsSetDecodeError) pure . eitherDecode
  >>= validateClaimsSet conf


-- | Cryptographically verify a JWS JWT, then validate the
-- Claims Set, returning it if valid.
--
-- This is the same as 'verifyClaims' except that the time is
-- explicitly provided.  If you process many requests per second
-- this will allow you to avoid unnecessary repeat system calls.
--
verifyClaimsAt
  ::
    ( HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , HasValidationSettings a
    , AsError e, AsJWTError e, MonadError e m
    , JWKStore k
    )
  => a
  -> k
  -> UTCTime
  -> SignedJWT
  -> m ClaimsSet
verifyClaimsAt a k t jwt = runReaderT (verifyClaims a k jwt) (WrappedUTCTime t)

-- | Create a JWS JWT
--
signClaims
  :: (MonadRandom m, MonadError e m, AsError e)
  => JWK
  -> JWSHeader ()
  -> ClaimsSet
  -> m SignedJWT
signClaims k h c =
  JWT <$> signJWS (encode c) (Identity (h, k))
