-- This file is part of jwt - JSON Web Token
-- Copyright (C) 2013  Fraser Tweedale
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

module Data.JWT where

import Control.Applicative
import Control.Monad
import Data.Maybe

import Data.Aeson
import Data.Attoparsec.Number
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Data.Time
import Data.Time.Clock.POSIX
import qualified Network.URI

import qualified Crypto.JOSE.JWK
import qualified Crypto.JOSE.JWS
import qualified Crypto.JOSE.Types


-- §2.  Terminology

data StringOrURI = Arbitrary T.Text | URI Network.URI.URI deriving (Eq, Show)

instance FromJSON StringOrURI where
  parseJSON = withText "StringOrURI" (\s ->
    if T.any (== ':') s
    then fmap URI $ maybe (fail "not a URI") pure $ Network.URI.parseURI $ T.unpack s
    else pure $ Arbitrary s)

instance ToJSON StringOrURI where
  toJSON (Arbitrary s)  = toJSON s
  toJSON (URI uri)      = toJSON $ show uri


newtype IntDate = IntDate UTCTime deriving (Eq, Show)

instance FromJSON IntDate where
  parseJSON = withNumber "IntDate" $
    pure . IntDate . posixSecondsToUTCTime . fromRational . toRational

instance ToJSON IntDate where
  toJSON (IntDate t) = Number $ I $ floor $ utcTimeToPOSIXSeconds t


-- §4.  JWT Claims

-- $4.1.3.  "aud" (Audience Claim)

data Audience = General [StringOrURI] | Special StringOrURI deriving (Eq, Show)

instance FromJSON Audience where
  parseJSON v = fmap General (parseJSON v) <|> fmap Special (parseJSON v)

instance ToJSON Audience where
  toJSON (General auds) = toJSON auds
  toJSON (Special aud)  = toJSON aud


data ClaimsSet = ClaimsSet {
  claimIss :: Maybe StringOrURI     -- Issuer Claim
  , claimSub :: Maybe StringOrURI   -- Subject Claim
  , claimAud :: Maybe Audience      -- Audience Claim
  -- §4.1.4.  "exp" (Expiration Time) Claim
  --
  -- processing of "exp" claim requires that current date/time
  -- MUST be before expiration date/time listed.  Implementers
  -- MAY provide leeway to account for clock skew.  Value MUST
  -- be a number containing an IntDate value
  , claimExp :: Maybe IntDate
  -- §4.1.4.  "nbf" (Not Before) Claim
  --
  -- processing of "nbf" claim requires that current date/time MUST
  -- be >= date/time listed.  Implementers MAY provide leeway to
  -- account for clock skew.  Value MUST be a number containing an
  -- IntDate value
  , claimNbf :: Maybe IntDate
  , claimIat :: Maybe IntDate -- Issued At
  , claimJti :: Maybe T.Text -- JWT ID; Case-insensitive string
  , unregisteredClaims :: M.HashMap T.Text Value
  }
  deriving (Eq, Show)

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


data JWT = JWS Crypto.JOSE.JWS.JWS ClaimsSet deriving (Eq, Show)

jwtClaimsSet :: JWT -> ClaimsSet
jwtClaimsSet (JWS _ c) = c

decodeJWT :: BSL.ByteString -> Maybe JWT
decodeJWT = Crypto.JOSE.JWS.decodeCompact >=> toJWT
  where
    toJWT jws = fmap (JWS jws) $ decodeClaims jws
    decodeClaims jws = decode (Crypto.JOSE.JWS.jwsPayload jws)

validateJWT :: Crypto.JOSE.JWK.Key -> JWT -> Bool
validateJWT k (JWS jws _) = Crypto.JOSE.JWS.validate k jws


data Header = JWSHeader Crypto.JOSE.JWS.Header  -- TODO JWE

createJWT :: Crypto.JOSE.JWK.Key -> Header -> ClaimsSet -> JWT
createJWT k (JWSHeader h) c = JWS jws c where
  payload = Crypto.JOSE.Types.Base64Octets $ BSL.toStrict $ encode c
  jws = Crypto.JOSE.JWS.sign (Crypto.JOSE.JWS.JWS payload []) h k
