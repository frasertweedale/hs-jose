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

module Crypto.JOSE.JWS where

import Control.Applicative
import Data.List
import Data.Maybe
import Data.Word

import Data.Aeson
import qualified Data.ByteString.Lazy as BS
import qualified Data.Text as T
import qualified Codec.Binary.Base64Url as B64

import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import qualified Crypto.JOSE.JWK as JWK


data Header = Header {
  alg :: JWA.JWS.Alg
  -- TODO other fields
  }
  deriving (Show)

instance FromJSON Header where
  parseJSON (Object o) = Header <$> o .: "alg"
  parseJSON _ = empty

instance ToJSON Header where
  toJSON (Header alg) = object [
    "alg" .= JWA.JWS.algToKey alg
    -- TODO other fields
    ]


data EncodedHeader = EncodedHeader Header
  deriving (Show)

instance FromJSON EncodedHeader where
  parseJSON (String s) = case B64.decode $ T.unpack s of
    Just bytes ->  case decode $ BS.pack bytes of
      Just h -> pure $ EncodedHeader h
      Nothing -> fail "signature header: invalid JSON"
    Nothing -> fail "signature header: invalid base64url"
  parseJSON _ = empty

instance ToJSON EncodedHeader where
  toJSON (EncodedHeader h) = String $ T.pack $ B64.encode $ BS.unpack $ encode h


data Signature = Signature Header String
  deriving (Show)

instance FromJSON Signature where
  parseJSON (Object o) = Signature <$>
    o .: "header" <*>
    o .: "signature"
  parseJSON _ = empty

instance ToJSON Signature where
  toJSON (Signature h s) = object ["header" .= h, "signature" .= s]


type Payload = String  -- already Base64URL encoded

data Signatures
  = Signatures (Maybe EncodedHeader) (Maybe Header) Payload [Signature]
    deriving (Show)

instance FromJSON Signatures where
  parseJSON (Object o) = Signatures <$>
    o .:? "protected" <*>
    o .:? "unprotected" <*>
    o .: "payload" <*>
    o .: "signatures"

instance ToJSON Signatures where
  toJSON (Signatures pro unpro payload sigs) = object fields where
    fields = pro' ++ unpro' ++ payload' ++ sigs'
    pro' = map ("protected" .=) $ maybeToList pro
    unpro' = map ("unprotected" .=) $ maybeToList unpro
    payload' = ["payload" .= payload]
    sigs' = ["signatures" .= sigs]

-- Convert Signatures to compact serialization.
--
-- The operation is defined only when there is exactly one
-- signature and returns Nothing otherwise
--
encodeCompact :: Signatures -> Maybe String
encodeCompact (Signatures (Just pro) _ payload [Signature _ s])
  = Just $ intercalate "." [pro', payload, s] where
    pro' = B64.encode $ BS.unpack $ encode pro
encodeCompact _ = Nothing


sign :: Signatures -> Header -> JWK.Key -> Signatures
sign (Signatures pro unpro p sigs) h k = Signatures pro unpro p (sig:sigs) where
  encodedHeader = B64.encode $ BS.unpack $ encode h
  signingInput = intercalate "." [encodedHeader, p]
  encodedSignature = B64.encode $ sign' (alg h) signingInput k
  sig = Signature h encodedSignature

sign' :: JWA.JWS.Alg -> String -> JWK.Key -> [Word8]
sign' JWA.JWS.None i _ = []
sign' _ _ _ = undefined


verify :: Signature -> JWK.Key -> Bool
verify = undefined

data VerifyData = Good | Bad | VerifyData [Word8]

runVerify :: Signature -> JWK.Key -> Maybe VerifyData
runVerify = undefined
