-- Copyright (C) 2013, 2014  Fraser Tweedale
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

{-|

JSON Web Token implementation.

-}
module Crypto.JWT
  (
    JWT(..)
  , createJWSJWT
  , validateJWSJWT

  , ClaimsSet(..)
  , emptyClaimsSet

  , Audience(..)

  , StringOrURI(..)
  , NumericDate(..)
  ) where

import Control.Applicative
import Control.Monad
import Data.Bifunctor
import Data.Maybe

import Data.Aeson
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Data.Time
import Data.Time.Clock.POSIX

import Crypto.JOSE
import Crypto.JOSE.Types


-- §2.  Terminology

-- | A JSON string value, with the additional requirement that while
--   arbitrary string values MAY be used, any value containing a /:/
--   character MUST be a URI.
--
data StringOrURI = Arbitrary T.Text | OrURI URI deriving (Eq, Show)

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
newtype NumericDate = NumericDate UTCTime deriving (Eq, Show)

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
data Audience = General [StringOrURI] | Special StringOrURI deriving (Eq, Show)

instance FromJSON Audience where
  parseJSON v = fmap General (parseJSON v) <|> fmap Special (parseJSON v)

instance ToJSON Audience where
  toJSON (General auds) = toJSON auds
  toJSON (Special aud)  = toJSON aud


-- | The JWT Claims Set represents a JSON object whose members are
--   the claims conveyed by the JWT.
--
data ClaimsSet = ClaimsSet
  { claimIss :: Maybe StringOrURI
  -- ^ The issuer claim identifies the principal that issued the
  -- JWT.  The processing of this claim is generally application
  -- specific.
  , claimSub :: Maybe StringOrURI
  -- ^ The subject claim identifies the principal that is the
  -- subject of the JWT.  The Claims in a JWT are normally
  -- statements about the subject.  The subject value MAY be scoped
  -- to be locally unique in the context of the issuer or MAY be
  -- globally unique.  The processing of this claim is generally
  -- application specific.
  , claimAud :: Maybe Audience
  -- ^ The audience claim identifies the recipients that the JWT is
  -- intended for.  Each principal intended to process the JWT MUST
  -- identify itself with a value in the audience claim.  If the
  -- principal processing the claim does not identify itself with a
  -- value in the /aud/ claim when this claim is present, then the
  -- JWT MUST be rejected.
  , claimExp :: Maybe NumericDate
  -- ^ The expiration time claim identifies the expiration time on
  -- or after which the JWT MUST NOT be accepted for processing.
  -- The processing of /exp/ claim requires that the current
  -- date\/time MUST be before expiration date\/time listed in the
  -- /exp/ claim.  Implementers MAY provide for some small leeway,
  -- usually no more than a few minutes, to account for clock skew.
  , claimNbf :: Maybe NumericDate
  -- ^ The not before claim identifies the time before which the JWT
  -- MUST NOT be accepted for processing.  The processing of the
  -- /nbf/ claim requires that the current date\/time MUST be after
  -- or equal to the not-before date\/time listed in the /nbf/
  -- claim.  Implementers MAY provide for some small leeway, usually
  -- no more than a few minutes, to account for clock skew.
  , claimIat :: Maybe NumericDate
  -- ^ The issued at claim identifies the time at which the JWT was
  -- issued.  This claim can be used to determine the age of the
  -- JWT.
  , claimJti :: Maybe T.Text
  -- ^ The JWT ID claim provides a unique identifier for the JWT.
  -- The identifier value MUST be assigned in a manner that ensures
  -- that there is a negligible probability that the same value will
  -- be accidentally assigned to a different data object.  The /jti/
  -- claim can be used to prevent the JWT from being replayed.  The
  -- /jti/ value is a case-sensitive string.
  , unregisteredClaims :: M.HashMap T.Text Value
  -- ^ Claim Names can be defined at will by those using JWTs.
  }
  deriving (Eq, Show)

-- | Return an empty claims set.
--
emptyClaimsSet :: ClaimsSet
emptyClaimsSet = ClaimsSet n n n n n n n M.empty where n = Nothing

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


-- | Data representing the JOSE aspects of a JWT.
--
data JWTCrypto = JWTJWS JWS deriving (Eq, Show)

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
    toJWT (JWTJWS jws) =
      bimap CompactDecodeError (JWT (JWTJWS jws))
        $ eitherDecode $ jwsPayload jws

instance ToCompact JWT where
  toCompact = toCompact . jwtCrypto


-- | Validate a JWT as a JWS (JSON Web Signature).
--
validateJWSJWT
  :: ValidationAlgorithms
  -> ValidationPolicy
  -> JWK
  -> JWT
  -> Bool
validateJWSJWT algs policy k (JWT (JWTJWS jws) _) = verifyJWS algs policy k jws

-- | Create a JWT that is a JWS.
--
createJWSJWT
  :: CPRG g
  => g
  -> JWK
  -> JWSHeader
  -> ClaimsSet
  -> (Either Error JWT, g)
createJWSJWT g k h c = first (fmap $ \jws -> JWT (JWTJWS jws) c) $
  signJWS g (JWS payload []) h k
  where
    payload = Base64Octets $ BSL.toStrict $ encode c
