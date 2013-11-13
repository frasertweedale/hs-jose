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
{-# LANGUAGE Rank2Types #-}

module Crypto.JOSE.JWS where

import Control.Applicative
import Data.Char
import Data.Maybe

import qualified Crypto.Classes as C
import Crypto.HMAC
import Crypto.Hash.CryptoAPI
import qualified Crypto.PubKey.RSA
import qualified Crypto.PubKey.RSA.PKCS15
import qualified Crypto.PubKey.HashDescr
import Data.Aeson
import Data.Aeson.Parser
import Data.Aeson.Types
import qualified Data.Attoparsec.ByteString.Lazy as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Data.Traversable (sequenceA)
import qualified Data.Vector as V

import qualified Crypto.JOSE.JWA.JWK as JWA.JWK
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

data CritParameters = CritParameters (M.HashMap T.Text Value)
  deriving (Eq, Show)

critObjectParser :: M.HashMap T.Text Value -> Value -> Parser (T.Text, Value)
critObjectParser o (String s)
  | s `elem` critInvalidNames = fail "crit key is reserved"
  | otherwise                 = (\v -> (s, v)) <$> o .: s
critObjectParser _ _          = fail "crit key is not text"

-- TODO implement array length >= 1 restriction
instance FromJSON CritParameters where
  parseJSON = withObject "crit" (\o ->
    case M.lookup "crit" o of
      Just (Array paramNames)
        | V.null paramNames -> fail "crit cannot be empty"
        | otherwise -> fmap (CritParameters . M.fromList)
          $ sequenceA
          $ map (critObjectParser o)
          $ V.toList paramNames
      _ -> fail "crit is not an array")

instance ToJSON CritParameters where
  toJSON (CritParameters m) = Object $ M.insert "crit" (toJSON $ M.keys m) m


data Header = Header
  { headerAlg :: JWA.JWS.Alg
  , headerJku :: Maybe Types.URI  -- JWK Set URL
  , headerJwk :: Maybe JWK.Key
  , headerX5u :: Maybe Types.URI
  , headerX5t :: Maybe Types.Base64SHA1
  , headerX5c :: Maybe [Types.Base64X509] -- TODO implement min len of 1
  , headerKid :: Maybe String  -- interpretation unspecified
  , headerTyp :: Maybe String  -- Content Type (of object)
  , headerCty :: Maybe String  -- Content Type (of payload)
  , headerCrit :: Maybe CritParameters
  , headerRaw :: Maybe BS.ByteString  -- protected header text as given
  }
  deriving (Show)

instance Eq Header where
  a == b =
    let
      ignoreRaw (Header alg jku jwk x5u x5t x5c kid typ cty crit _)
        = (alg, jku, jwk, x5u, x5t, x5c, kid, typ, cty, crit)
    in
      ignoreRaw a == ignoreRaw b

parseHeaderWith
  :: (forall a. FromJSON a => T.Text -> Parser a)
  -> (forall a. FromJSON a => T.Text -> Parser (Maybe a))
  -> Parser (Maybe CritParameters)
  -> Parser Header
parseHeaderWith req opt crit = Header
    <$> req "alg"
    <*> opt "jku"
    <*> opt "jwk"
    <*> opt "x5u"
    <*> opt "x5t"
    <*> opt "x5c"
    <*> opt "kid"
    <*> opt "typ"
    <*> opt "cty"
    <*> crit
    <*> pure Nothing

parseCrit :: Object -> Parser (Maybe CritParameters)
parseCrit o = if M.member "crit" o
  then Just <$> parseJSON (Object o)
  else pure Nothing

instance FromJSON Header where
  parseJSON = withObject "JWS Header" (\o ->
    parseHeaderWith (o .:) (o .:?) (parseCrit o))

instance ToJSON Header where
  toJSON (Header alg jku jwk x5u x5t x5c kid typ cty crit _) = object $ catMaybes [
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
algHeader alg = Header alg n n n n n n n n n n where n = Nothing


(.::) :: (FromJSON a) => Object -> Object -> T.Text -> Parser a
(.::) o1 o2 k = case (M.lookup k o1, M.lookup k o2) of
  (Just _, Just _)  -> fail $ "key " ++ show k ++ " cannot appear twice"
  (Just v, _)       -> parseJSON v
  (_, Just v)       -> parseJSON v
  _                 -> fail $ "key " ++ show k ++ " now present"

(.::?) :: (FromJSON a) => Object -> Object -> T.Text -> Parser (Maybe a)
(.::?) o1 o2 k = case (M.lookup k o1, M.lookup k o2) of
  (Just _, Just _)  -> fail $ "key " ++ show k ++ " cannot appear twice"
  (Just v, _)       -> parseJSON v
  (_, Just v)       -> parseJSON v
  _                 -> pure Nothing


data Signature = Signature Header Types.Base64Octets
  deriving (Eq, Show)

parseHeader :: Maybe Object -> Maybe Object -> Parser Header
parseHeader (Just p) (Just u) = parseHeaderWith ((.::) p u) ((.::?) p u) (parseCrit p)
parseHeader (Just p) _ = parseHeaderWith (p .:) (p .:?) (parseCrit p)
parseHeader _ (Just u) = parseHeaderWith (u .:) (u .:?) (if M.member "crit" u
  then fail "crit MUST occur only with the JWS Protected Header"
  else pure Nothing)
parseHeader _ _ = fail "no protected or unprotected header given"

instance FromJSON Signature where
  parseJSON = withObject "signature" (\o -> Signature
    <$> do
      protectedEncoded <- o .:? "protected"
      protectedJSON <- maybe
        (pure Nothing)
        (withText "base64 encoded header" (Types.parseB64Url (return . Just)))
        protectedEncoded
      protected <- maybe
        (pure Nothing)
        (return . decode . BSL.fromStrict)
        protectedJSON
      unprotected <- o .:? "header"
      parseHeader protected unprotected
    <*> o .: "signature")

instance ToJSON Signature where
  toJSON (Signature h s) = object $ ("signature" .= s) : Types.objectPairs (toJSON h)


data JWS = JWS Types.Base64Octets [Signature]
  deriving (Eq, Show)

instance FromJSON JWS where
  parseJSON = withObject "JWS JSON serialization" (\o -> JWS
    <$> o .: "payload"
    <*> o .: "signatures")

instance ToJSON JWS where
  toJSON (JWS p ss) = object ["payload" .= p, "signatures" .= ss]

jwsPayload :: JWS -> BSL.ByteString
jwsPayload (JWS (Types.Base64Octets s) _) = BSL.fromStrict s


encodeO :: ToJSON a => a -> BSL.ByteString
encodeO = BSL.reverse . BSL.dropWhile (== c) . BSL.reverse
  . B64UL.encode . encode
  where c = fromIntegral $ ord '='

decodeO :: FromJSON a => BSL.ByteString -> Either String a
decodeO s = B64UL.decode (pad s) >>= eitherDecode
  where
    pad t = t `BSL.append` BSL.replicate ((4 - BSL.length t `mod` 4) `mod` 4) c
    c = fromIntegral $ ord '='

encodeS :: ToJSON a => a -> BSL.ByteString
encodeS = BSL.init . BSL.tail . encode

decodeS :: FromJSON a => BSL.ByteString -> Maybe a
decodeS s = do
  v <- A.maybeResult $ A.parse value $ BSL.intercalate s ["\"", "\""]
  parseMaybe parseJSON v

signingInput :: Header -> Types.Base64Octets -> BSL.ByteString
signingInput h p = BSL.intercalate "."
  [maybe (encodeO h) BSL.fromStrict (headerRaw h), encodeS p]

-- Convert JWS to compact serialization.
--
-- The operation is defined only when there is exactly one
-- signature and returns Nothing otherwise
--
encodeCompact :: JWS -> Maybe BSL.ByteString
encodeCompact (JWS p [Signature h s]) = Just $
  BSL.intercalate "." [signingInput h p, encodeS s]
encodeCompact _ = Nothing

eitherDecodeCompact :: BSL.ByteString -> Either String JWS
eitherDecodeCompact t = do
  [h, p, s] <- threeParts $ BSL.split 46 t
  h' <- fmap (\h' -> h' { headerRaw = Just $ BSL.toStrict h }) $ decodeO h
  p' <- maybe (Left "payload decode failed") Right $ decodeS p
  s' <- maybe (Left "sig decode failed") Right $ decodeS s
  return $ JWS p' [Signature h' s']
  where
    threeParts [h, p, s] = Right [h, p, s]
    threeParts _ = Left "incorrect number of parts"

decodeCompact :: BSL.ByteString -> Maybe JWS
decodeCompact = either (const Nothing) Just . eitherDecodeCompact


-- §5.1. Message Signing or MACing

sign :: JWS -> Header -> JWK.Key -> JWS
sign (JWS p sigs) h k = JWS p (sig:sigs) where
  sig = Signature h $ Types.Base64Octets $ sign' (headerAlg h) (signingInput h p) k

keyBytes :: JWK.Key -> BS.ByteString
keyBytes k = case JWK.keyMaterial k of
  JWA.JWK.ECKeyMaterial _ _ -> undefined
  JWA.JWK.RSAKeyMaterial _ _ -> undefined
  JWA.JWK.OctKeyMaterial _ (Types.Base64Octets s) -> s

keyRSAPrivate :: JWK.Key -> Crypto.PubKey.RSA.PrivateKey
keyRSAPrivate k = case JWK.keyMaterial k of
  JWA.JWK.ECKeyMaterial _ _ -> undefined
  JWA.JWK.RSAKeyMaterial _ (JWA.JWK.RSAPrivateKeyParameters
    (Types.SizedBase64Integer size n)
    (Types.Base64Integer e)
    (Types.Base64Integer d)
    _) ->
      Crypto.PubKey.RSA.PrivateKey
        (Crypto.PubKey.RSA.PublicKey size n e)
        d 0 0 0 0 0
  JWA.JWK.RSAKeyMaterial _ (JWA.JWK.RSAPublicKeyParameters _ _) ->
    error "not an RSA private key"
  JWA.JWK.OctKeyMaterial _ _ -> undefined

sign' :: JWA.JWS.Alg -> BSL.ByteString -> JWK.Key -> BS.ByteString
sign' JWA.JWS.None _ _ = ""
sign' JWA.JWS.HS256 s k = C.encode (hmac (MacKey $ keyBytes k) s :: SHA256)
sign' JWA.JWS.RS256 s k = either (error . show) id $
  Crypto.PubKey.RSA.PKCS15.sign
  Nothing
  Crypto.PubKey.HashDescr.hashDescrSHA256
  (keyRSAPrivate k)
  (BSL.toStrict s)
sign' alg _ _ = error $ "algorithm " ++ show alg ++ " not implemented"

validate :: JWK.Key -> JWS -> Bool
validate k (JWS p sigs) = any (validateSig k p) sigs

validateSig :: JWK.Key -> Types.Base64Octets -> Signature -> Bool
validateSig k p (Signature h (Types.Base64Octets m))
  = sign' (headerAlg h) (signingInput h p) k == m

validateDecode :: JWK.Key -> BSL.ByteString -> Bool
validateDecode k = maybe False (validate k) . decode

validateDecodeCompact :: JWK.Key -> BSL.ByteString -> Bool
validateDecodeCompact k = maybe False (validate k) . decodeCompact
