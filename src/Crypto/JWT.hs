-- This file is part of jwt - JSON Web Token
-- Copyright (C) 2013, 2014  Fraser Tweedale
--
-- jwt is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
  , IntDate(..)
  ) where

import Control.Applicative
import Control.Arrow
import Control.Monad
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
newtype IntDate = IntDate UTCTime deriving (Eq, Show)

instance FromJSON IntDate where
  parseJSON = withScientific "IntDate" $
    pure . IntDate . posixSecondsToUTCTime . fromRational . toRational

instance ToJSON IntDate where
  toJSON (IntDate t)
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
  , claimExp :: Maybe IntDate
  -- ^ The expiration time claim identifies the expiration time on
  -- or after which the JWT MUST NOT be accepted for processing.
  -- The processing of /exp/ claim requires that the current
  -- date\/time MUST be before expiration date\/time listed in the
  -- /exp/ claim.  Implementers MAY provide for some small leeway,
  -- usually no more than a few minutes, to account for clock skew.
  , claimNbf :: Maybe IntDate
  -- ^ The not before claim identifies the time before which the JWT
  -- MUST NOT be accepted for processing.  The processing of the
  -- /nbf/ claim requires that the current date\/time MUST be after
  -- or equal to the not-before date\/time listed in the /nbf/
  -- claim.  Implementers MAY provide for some small leeway, usually
  -- no more than a few minutes, to account for clock skew.
  , claimIat :: Maybe IntDate
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
      either (Left . CompactDecodeError) (Right . JWT (JWTJWS jws))
        $ eitherDecode $ jwsPayload jws

instance ToCompact JWT where
  toCompact = toCompact . jwtCrypto


-- | Validate a JWT as a JWS (JSON Web Signature).
--
validateJWSJWT :: JWK -> JWT -> Bool
validateJWSJWT k (JWT (JWTJWS jws) _) = verifyJWS k jws

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
