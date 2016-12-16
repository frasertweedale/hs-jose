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

{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE UndecidableInstances #-}

{-|

JSON Web Token implementation.

-}
module Crypto.JWT
  (
    JWT(..)
  , JWTCrypto(..)
  , JWTError(..)
  , AsJWTError(..)

  , JWTValidationSettings
  , defaultJWTValidationSettings
  , HasJWTValidationSettings(..)
  , HasAllowedSkew(..)
  , HasAudiencePredicate(..)
  , HasIssuerPredicate(..)
  , HasCheckIssuedAt(..)

  , createJWSJWT
  , validateJWSJWT

  , ClaimsSet(..) -- TODO hide fields
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

  , Audience(..)

  , StringOrURI
  , fromString
  , fromURI
  , getString
  , getURI

  , NumericDate(..)
  ) where

import Control.Applicative
import Control.Monad
import Control.Monad.Time (MonadTime(..))
#if ! MIN_VERSION_monad_time(0,2,0)
import Control.Monad.Time.Instances ()
#endif
import Data.Maybe
import qualified Data.String

import Control.Lens (
  makeClassy, makeClassyPrisms, makeLenses, makePrisms,
  Lens', _Just, over, preview, review, view)
import Control.Monad.Except (MonadError(throwError))
import Data.Aeson
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Data.Time (NominalDiffTime, UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime, utcTimeToPOSIXSeconds)
import Network.URI (parseURI)

import Crypto.JOSE
import Crypto.JOSE.Types


data JWTError
  = JWSError Error
  | JWTExpired
  | JWTNotYetValid
  | JWTNotInIssuer
  | JWTNotInAudience
  | JWTIssuedAtFuture
  deriving (Eq, Show)
makeClassyPrisms ''JWTError

instance AsError JWTError where
  _Error = _JWSError


-- §2.  Terminology

-- | A JSON string value, with the additional requirement that while
--   arbitrary string values MAY be used, any value containing a /:/
--   character MUST be a URI.
--
data StringOrURI = Arbitrary T.Text | OrURI URI deriving (Eq, Show)

instance Data.String.IsString StringOrURI where
  fromString = Arbitrary . T.pack

-- | Construct a 'StringOrURI' from text
--
fromString :: T.Text -> StringOrURI
fromString s = maybe (Arbitrary s) OrURI $ parseURI $ T.unpack s

-- | Construct a 'StringOrURI' from a URI
--
fromURI :: URI -> StringOrURI
fromURI = OrURI

-- | Get the
getString :: StringOrURI -> Maybe T.Text
getString (Arbitrary a) = Just a
getString (OrURI _) = Nothing

-- | Get the uri from a 'StringOrURI'
--
getURI :: StringOrURI -> Maybe URI
getURI (Arbitrary _) = Nothing
getURI (OrURI a) = Just a

instance FromJSON StringOrURI where
  parseJSON = withText "StringOrURI" (\s ->
    if T.any (== ':') s
    then OrURI <$> parseJSON (String s)
    else pure $ Arbitrary s)

instance ToJSON StringOrURI where
  toJSON (Arbitrary s)  = toJSON s
  toJSON (OrURI uri)    = toJSON $ show uri


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
newtype Audience = Audience [StringOrURI] deriving (Eq, Show)
makePrisms ''Audience

instance FromJSON Audience where
  parseJSON v = Audience <$> (parseJSON v <|> fmap (:[]) (parseJSON v))

instance ToJSON Audience where
  toJSON (Audience [aud]) = toJSON aud
  toJSON (Audience auds) = toJSON auds


-- | The JWT Claims Set represents a JSON object whose members are
--   the claims conveyed by the JWT.
--
data ClaimsSet = ClaimsSet
  { _claimIss :: Maybe StringOrURI
  -- ^ The issuer claim identifies the principal that issued the
  -- JWT.  The processing of this claim is generally application
  -- specific.
  , _claimSub :: Maybe StringOrURI
  -- ^ The subject claim identifies the principal that is the
  -- subject of the JWT.  The Claims in a JWT are normally
  -- statements about the subject.  The subject value MAY be scoped
  -- to be locally unique in the context of the issuer or MAY be
  -- globally unique.  The processing of this claim is generally
  -- application specific.
  , _claimAud :: Maybe Audience
  -- ^ The audience claim identifies the recipients that the JWT is
  -- intended for.  Each principal intended to process the JWT MUST
  -- identify itself with a value in the audience claim.  If the
  -- principal processing the claim does not identify itself with a
  -- value in the /aud/ claim when this claim is present, then the
  -- JWT MUST be rejected.
  , _claimExp :: Maybe NumericDate
  -- ^ The expiration time claim identifies the expiration time on
  -- or after which the JWT MUST NOT be accepted for processing.
  -- The processing of /exp/ claim requires that the current
  -- date\/time MUST be before expiration date\/time listed in the
  -- /exp/ claim.  Implementers MAY provide for some small leeway,
  -- usually no more than a few minutes, to account for clock skew.
  , _claimNbf :: Maybe NumericDate
  -- ^ The not before claim identifies the time before which the JWT
  -- MUST NOT be accepted for processing.  The processing of the
  -- /nbf/ claim requires that the current date\/time MUST be after
  -- or equal to the not-before date\/time listed in the /nbf/
  -- claim.  Implementers MAY provide for some small leeway, usually
  -- no more than a few minutes, to account for clock skew.
  , _claimIat :: Maybe NumericDate
  -- ^ The issued at claim identifies the time at which the JWT was
  -- issued.  This claim can be used to determine the age of the
  -- JWT.
  , _claimJti :: Maybe T.Text
  -- ^ The JWT ID claim provides a unique identifier for the JWT.
  -- The identifier value MUST be assigned in a manner that ensures
  -- that there is a negligible probability that the same value will
  -- be accidentally assigned to a different data object.  The /jti/
  -- claim can be used to prevent the JWT from being replayed.  The
  -- /jti/ value is a case-sensitive string.
  , _unregisteredClaims :: M.HashMap T.Text Value
  -- ^ Claim Names can be defined at will by those using JWTs.
  }
  deriving (Eq, Show)
makeLenses ''ClaimsSet

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

class HasAllowedSkew s where
  allowedSkew :: Lens' s NominalDiffTime
class HasAudiencePredicate s where
  audiencePredicate :: Lens' s (StringOrURI -> Bool)
class HasIssuerPredicate s where
  issuerPredicate :: Lens' s (StringOrURI -> Bool)
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

defaultJWTValidationSettings :: JWTValidationSettings
defaultJWTValidationSettings = JWTValidationSettings
  defaultValidationSettings
  0
  True
  (const False)
  (const True)

-- | Validate the claims made by a ClaimsSet. Currently only inspects
-- the /exp/ and /nbf/ claims. N.B. These checks are also performed by
-- 'validateJWSJWT', which also validates any signatures, so you
-- shouldn’t need to use this directly in the normal course of things.
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
  -> m ()
validateClaimsSet conf claims =
  sequence_
    [ validateExpClaim conf claims
    , validateIatClaim conf claims
    , validateNbfClaim conf claims
    , validateIssClaim conf claims
    , validateAudClaim conf claims
    ]

validateExpClaim
  :: (MonadTime m, HasAllowedSkew a, AsJWTError e, MonadError e m)
  => a
  -> ClaimsSet
  -> m ()
validateExpClaim conf (ClaimsSet _ _ _ (Just e) _ _ _ _) = do
  now <- currentTime
  if now < addUTCTime (abs (view allowedSkew conf)) (view _NumericDate e)
    then pure ()
    else throwError (review _JWTExpired ())
validateExpClaim _ _ = pure ()

validateIatClaim
  :: (MonadTime m, HasCheckIssuedAt a, HasAllowedSkew a, AsJWTError e, MonadError e m)
  => a
  -> ClaimsSet
  -> m ()
validateIatClaim conf (ClaimsSet _ _ _ _ _ (Just t) _ _) = do
  now <- currentTime
  when (view checkIssuedAt conf) $
    when ((view _NumericDate t) > addUTCTime (abs (view allowedSkew conf)) now) $
    throwError (review _JWTIssuedAtFuture ())
validateIatClaim _ _ = pure ()

validateNbfClaim
  :: (MonadTime m, HasAllowedSkew a, AsJWTError e, MonadError e m)
  => a
  -> ClaimsSet
  -> m ()
validateNbfClaim conf (ClaimsSet _ _ _ _ (Just n) _ _ _) = do
  now <- currentTime
  if now >= addUTCTime (negate (abs (view allowedSkew conf))) (view _NumericDate n)
    then pure ()
    else throwError (review _JWTNotYetValid ())
validateNbfClaim _ _ = pure ()

validateAudClaim
  :: (HasAudiencePredicate s, AsJWTError e, MonadError e m)
  => s
  -> ClaimsSet
  -> m ()
validateAudClaim conf claims =
  maybe
    (pure ())
    (\auds ->
      if or (view audiencePredicate conf <$> auds)
      then pure ()
      else throwError (review _JWTNotInAudience ())
      )
    (preview (claimAud . _Just . _Audience) claims)

validateIssClaim
  :: (HasIssuerPredicate s, AsJWTError e, MonadError e m)
  => s
  -> ClaimsSet
  -> m ()
validateIssClaim conf claims =
  maybe
    (pure ())
    (\iss ->
      if view issuerPredicate conf iss
      then pure ()
      else throwError (review _JWTNotInIssuer ())
      )
    (preview (claimIss . _Just) claims)

-- | Data representing the JOSE aspects of a JWT.
--
data JWTCrypto = JWTJWS (JWS JWSHeader) deriving (Eq, Show)

instance FromCompact JWTCrypto where
  fromCompact = fmap JWTJWS . fromCompact

instance ToCompact JWTCrypto where
  toCompact (JWTJWS jws) = toCompact jws


-- | JSON Web Token data.
--
data JWT = JWT
  { jwtCrypto     :: JWTCrypto  -- ^ JOSE aspect of the JWT.
  , jwtClaimsSet  :: ClaimsSet  -- ^ Claims of the JWT.
  } deriving (Eq, Show)

instance FromCompact JWT where
  fromCompact = fromCompact >=> toJWT where
    toJWT (JWTJWS jws) = either
      (throwError . review _CompactDecodeError)
      (pure . JWT (JWTJWS jws))
      (eitherDecode $ jwsPayload jws)

instance ToCompact JWT where
  toCompact = toCompact . jwtCrypto


-- | Validate a JWT as a JWS (JSON Web Signature), then as a Claims
-- Set.
--
validateJWSJWT
  ::
    ( MonadTime m, HasAllowedSkew a, HasAudiencePredicate a
    , HasIssuerPredicate a
    , HasCheckIssuedAt a
    , HasValidationSettings a
    , AsError e, AsJWTError e, MonadError e m
    )
  => a
  -> JWK
  -> JWT
  -> m ()
validateJWSJWT conf k (JWT (JWTJWS jws) c) = do
  -- It is important, for security reasons, that the signature get
  -- verified before the claims.
  verifyJWS conf k jws >> validateClaimsSet conf c

-- | Create a JWT that is a JWS.
--
createJWSJWT
  :: (MonadRandom m, MonadError e m, AsError e)
  => JWK
  -> JWSHeader
  -> ClaimsSet
  -> m JWT
createJWSJWT k h c =
  (\jws -> JWT (JWTJWS jws) c) <$> signJWS (JWS payload []) h k
  where
    payload = Base64Octets $ BSL.toStrict $ encode c
