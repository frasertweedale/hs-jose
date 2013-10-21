-- This file is part of jose - web crypto library
-- Copyright (C) 2013  Fraser Tweedale
--
-- jose is free software: you can redistribute it and/or modify
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
{-# LANGUAGE PatternGuards #-}

module Crypto.JOSE.JWS where

import Control.Applicative
import Data.Maybe
import Data.Word

import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Data.Traversable (sequenceA)
import qualified Data.Vector as V
import qualified Network.URI

import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.Types as Types


critInvalidNames :: [T.Text]
critInvalidNames = [
  "alg"
  , "jku"
  , "jwk"
  , "x5u"
  , "x5t"
  , "x5c"
  , "kid"
  , "typ"
  , "cty"
  , "crit"
  ]

data CritParameters
  = CritParameters (M.HashMap T.Text Value)
  | NullCritParameters
  deriving (Eq, Show)

critObjectParser :: M.HashMap T.Text Value -> Value -> Parser (T.Text, Value)
critObjectParser o (String s)
  | s `elem` critInvalidNames = fail "crit key is reserved"
  | otherwise                 = (\v -> (s, v)) <$> o .: s
critObjectParser _ _          = fail "crit key is not text"

-- TODO implement array length >= 1 restriction
instance FromJSON CritParameters where
  parseJSON (Object o)
    | Just (Array paramNames) <- M.lookup "crit" o
    = fmap (CritParameters . M.fromList)
      $ sequenceA
      $ map (critObjectParser o)
      $ V.toList paramNames
    | Just _ <- M.lookup "crit" o
    = fail "crit is not an array"
    | otherwise  -- no "crit" param at all
    = pure NullCritParameters
  parseJSON _ = fail "not an object"

instance ToJSON CritParameters where
  toJSON (CritParameters m) = Object $ M.insert "crit" (toJSON $ M.keys m) m
  toJSON (NullCritParameters) = object []


data Header = Header {
  headerAlg :: JWA.JWS.Alg
  , headerJku :: Maybe Network.URI.URI  -- JWK Set URL
  , headerJwk :: Maybe JWK.Key
  , headerX5u :: Maybe Network.URI.URI
  , headerX5t :: Maybe Types.Base64SHA1
  , headerX5c :: Maybe [Types.Base64X509] -- TODO implement min len of 1
  , headerKid :: Maybe String  -- interpretation unspecified
  , headerTyp :: Maybe String  -- Content Type (of object)
  , headerCty :: Maybe String  -- Content Type (of payload)
  , headerCrit :: CritParameters
  }
  deriving (Eq, Show)

instance FromJSON Header where
  parseJSON = withObject "JWS Header" (\o -> Header
    <$> o .: "alg"
    <*> o .:? "jku"
    <*> o .:? "jwk"
    <*> o .:? "x5u"
    <*> o .:? "x5t"
    <*> o .:? "x5c"
    <*> o .:? "kid"
    <*> o .:? "typ"
    <*> o .:? "cty"
    <*> parseJSON (Object o))

instance ToJSON Header where
  toJSON (Header alg jku jwk x5u x5t x5c kid typ cty crit) = object $ catMaybes [
    Just ("alg" .= alg)
    , fmap ("jku" .=) jku
    , fmap ("jwk" .=) jwk
    , fmap ("x5u" .=) x5u
    , fmap ("x5t" .=) x5t
    , fmap ("x5c" .=) x5c
    , fmap ("kid" .=) kid
    , fmap ("typ" .=) typ
    , fmap ("cty" .=) cty
    ]
    ++ Types.objectPairs (toJSON crit)


-- construct a minimal header with the given alg
algHeader :: JWA.JWS.Alg -> Header
algHeader alg = Header alg
  Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing
  NullCritParameters


data EncodedHeader
  = EncodedHeader Header
  | MockEncodedHeader BS.ByteString
  deriving (Eq, Show)

instance FromJSON EncodedHeader where
  parseJSON = withText "JWS Encoded Header" $ Types.parseB64Url $
    maybe (fail "not a valid header") (pure . EncodedHeader) . decode . BSL.fromStrict

instance ToJSON EncodedHeader where
  toJSON (MockEncodedHeader s) = Types.encodeB64Url s
  toJSON (EncodedHeader h) = Types.encodeB64Url $ BSL.toStrict $ encode h


-- TODO: implement following restriction
--
-- §7.2. JWS JSON Serialization
--
--  Of these members, only the "payload", "signatures", and "signature"
--  members MUST be present.  At least one of the "protected" and
--  "header" members MUST be present for each signature/MAC computation
--  so that an "alg" Header Parameter value is conveyed.
--
data Headers =
  Protected EncodedHeader
  | Unprotected Header
  | Both EncodedHeader Header
  deriving (Eq, Show)

instance FromJSON Headers where
  parseJSON = withObject "JWS headers" (\o ->
    Both            <$> o .: "protected" <*> o .: "header"
    <|> Protected   <$> o .: "protected"
    <|> Unprotected <$> o .: "header")

instance ToJSON Headers where
  toJSON (Both p u)       = object ["protected" .= p, "header" .= u]
  toJSON (Protected p)    = object ["protected" .= p]
  toJSON (Unprotected u)  = object ["header" .= u]

-- Select the header to be used as the JWS Protected Header
--
protectedHeader :: Headers -> EncodedHeader
protectedHeader (Protected h)   = h
protectedHeader (Unprotected h) = EncodedHeader h
protectedHeader (Both h _)      = h


data Signature = Signature Headers BSL.ByteString
  deriving (Eq, Show)

instance FromJSON Signature where
  parseJSON = withObject "signature" (\o -> Signature
    <$> o .: "protected"
    <*> parseJSON (Object o))

instance ToJSON Signature where
  toJSON (Signature h s) = object $ ("signature" .= s) : Types.objectPairs (toJSON h)


data Signatures = Signatures Types.Base64Octets [Signature]
  deriving (Eq, Show)

instance FromJSON Signatures where
  parseJSON = withObject "JWS JSON serialization" (\o -> Signatures
    <$> o .: "payload"
    <*> o .: "signatures")

instance ToJSON Signatures where
  toJSON (Signatures p ss) = object ["payload" .= p, "signatures" .= ss]


-- Convert Signatures to compact serialization.
--
-- The operation is defined only when there is exactly one
-- signature and returns Nothing otherwise
--
encodeCompact :: Signatures -> Maybe BSL.ByteString
encodeCompact (Signatures p [Signature h s]) = Just $ BSL.intercalate "." [signingInput h p, s]
encodeCompact _ = Nothing


-- §5.1. Message Signing or MACing

encode' :: ToJSON a => a -> BSL.ByteString
encode' = BSL.init . BSL.tail . encode

signingInput :: Headers -> Types.Base64Octets -> BSL.ByteString
signingInput h p' = BSL.intercalate "." [encode' $ protectedHeader h, encode' p']

alg' :: Headers -> JWA.JWS.Alg
alg' (Both (EncodedHeader h) _)     = headerAlg h
alg' (Protected (EncodedHeader h))  = headerAlg h
alg' (Unprotected h)                = headerAlg h
alg' _                              = undefined

sign :: Signatures -> Headers -> JWK.Key -> Signatures
sign (Signatures p sigs) h k = Signatures p (sig:sigs) where
  sig = Signature h $ B64UL.encode $ sign' (alg' h) (signingInput h p) k

sign' :: JWA.JWS.Alg -> BSL.ByteString -> JWK.Key -> BSL.ByteString
sign' JWA.JWS.None _ _ = ""
sign' _ _ _ = undefined


verify :: Signature -> JWK.Key -> Bool
verify = undefined

data VerifyData = Good | Bad | VerifyData [Word8]

runVerify :: Signature -> JWK.Key -> Maybe VerifyData
runVerify = undefined
