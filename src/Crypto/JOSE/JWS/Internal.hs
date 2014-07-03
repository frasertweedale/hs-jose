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
{-# LANGUAGE Rank2Types #-}
{-# OPTIONS_HADDOCK hide #-}

module Crypto.JOSE.JWS.Internal where

import Control.Applicative
import Control.Arrow
import Data.Char
import Data.Maybe

import Data.Aeson
import Data.Aeson.Parser
import Data.Aeson.Types
import qualified Data.Attoparsec.ByteString.Lazy as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as E
import Data.Traversable (sequenceA)
import qualified Data.Vector as V

import Crypto.JOSE.Classes
import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types


critInvalidNames :: [T.Text]
critInvalidNames = [
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


-- | JWS Header data type.
data Header = Header
  { headerAlg :: JWA.JWS.Alg
  , headerJku :: Maybe Types.URI  -- ^ JWK Set URL
  , headerJwk :: Maybe JWK
  , headerKid :: Maybe String  -- ^ interpretation unspecified
  , headerX5u :: Maybe Types.URI
  , headerX5c :: Maybe [Types.Base64X509] -- ^ TODO implement min len of 1
  , headerX5t :: Maybe Types.Base64SHA1
  , headerX5tS256 :: Maybe Types.Base64SHA256
  , headerTyp :: Maybe String  -- ^ Content Type (of object)
  , headerCty :: Maybe String  -- ^ Content Type (of payload)
  , headerCrit :: Maybe CritParameters
  , headerRaw :: Maybe BS.ByteString  -- ^ protected header, if known
  }
  deriving (Show)

instance Eq Header where
  a == b =
    let
      ignoreRaw (Header alg jku jwk kid x5u x5c x5t x5tS256 typ cty crit _)
        = (alg, jku, jwk, kid, x5u, x5c, x5t, x5tS256, typ, cty, crit)
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
    <*> opt "kid"
    <*> opt "x5u"
    <*> opt "x5t"
    <*> opt "x5t#S256"
    <*> opt "x5c"
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
  toJSON (Header alg jku jwk kid x5u x5c x5t x5tS256 typ cty crit _) = object $ catMaybes [
    Just ("alg" .= alg)
    , fmap ("jku" .=) jku
    , fmap ("jwk" .=) jwk
    , fmap ("kid" .=) kid
    , fmap ("x5u" .=) x5u
    , fmap ("x5c" .=) x5c
    , fmap ("x5t" .=) x5t
    , fmap ("x5t#S256" .=) x5tS256
    , fmap ("typ" .=) typ
    , fmap ("cty" .=) cty
    ]
    ++ Types.objectPairs (toJSON crit)


-- construct a minimal header with the given alg
algHeader :: JWA.JWS.Alg -> Header
algHeader alg = Header alg n n n n n n n n n n n where n = Nothing


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


newtype JSONByteString = JSONByteString { bs :: BS.ByteString }

instance FromJSON JSONByteString where
  parseJSON = withText "JSON bytestring" (return . JSONByteString . E.encodeUtf8)

instance FromJSON Signature where
  parseJSON = withObject "signature" (\o -> Signature
    <$> do
      protectedEncoded <- o .:? "protected"
      protectedJSON <- maybe
        (pure Nothing)
        (withText "base64 encoded header"
          (Types.parseB64Url (return . Just . JSONByteString)))
        protectedEncoded
      protected <- maybe
        (pure Nothing)
        (return . decode . BSL.fromStrict)
        (fmap bs protectedJSON)
      unprotected <- o .:? "header"
      parseHeader protected unprotected
    <*> o .: "signature")

instance ToJSON Signature where
  toJSON (Signature h s) = object $ ("signature" .= s) : Types.objectPairs (toJSON h)


-- | JSON Web Signature data type.  Consists of a payload and a
-- (possibly empty) list of signatures.
--
data JWS = JWS Types.Base64Octets [Signature]
  deriving (Eq, Show)

instance FromJSON JWS where
  parseJSON = withObject "JWS JSON serialization" (\o -> JWS
    <$> o .: "payload"
    <*> o .: "signatures")

instance ToJSON JWS where
  toJSON (JWS p ss) = object ["payload" .= p, "signatures" .= ss]

-- | Payload of a JWS, as a lazy bytestring.
--
jwsPayload :: JWS -> BSL.ByteString
jwsPayload (JWS (Types.Base64Octets s) _) = BSL.fromStrict s


encodeO :: ToJSON a => a -> BSL.ByteString
encodeO = BSL.reverse . BSL.dropWhile (== c) . BSL.reverse
  . B64UL.encode . encode
  where c = fromIntegral $ ord '='

encodeS :: ToJSON a => a -> BSL.ByteString
encodeS = BSL.init . BSL.tail . encode

signingInput :: Header -> Types.Base64Octets -> BSL.ByteString
signingInput h p = BSL.intercalate "."
  [maybe (encodeO h) BSL.fromStrict (headerRaw h), encodeS p]

-- Convert JWS to compact serialization.
--
-- The operation is defined only when there is exactly one
-- signature and returns Nothing otherwise
--
instance ToCompact JWS where
  toCompact (JWS p [Signature h s]) = Right [signingInput h p, encodeS s]
  toCompact (JWS _ xs) = Left $ CompactEncodeError $
    "cannot compact serialize JWS with " ++ show (length xs) ++ " sigs"

instance FromCompact JWS where
  fromCompact xs = case xs of
    [h, p, s] -> do
      h' <- (\h' -> h' { headerRaw = Just $ BSL.toStrict h })
        <$> decodeO "header" h
      p' <- decodeS "payload" p
      s' <- decodeS "signature" s
      return $ JWS p' [Signature h' s']
    xs' -> compactErr "compact representation"
      $ "expected 3 parts, got " ++ show (length xs')
    where
      compactErr s = Left . CompactDecodeError . ((s ++ " decode failed: ") ++)
      jsonErr = Left . JSONDecodeError
      decodeO desc s =
        either (compactErr desc) Right (B64UL.decode (pad s))
        >>= either jsonErr Right . eitherDecode
      decodeS desc s =
        either (compactErr desc) Right
          (A.eitherResult $ A.parse value $ BSL.intercalate s ["\"", "\""])
        >>= either jsonErr Right . parseEither parseJSON
      pad t = t `BSL.append` BSL.replicate ((4 - BSL.length t `mod` 4) `mod` 4) c
      c = fromIntegral $ ord '='


-- §5.1. Message Signing or MACing

-- | Create a new signature on a JWS.
--
signJWS
  :: CPRG g
  => g        -- ^ Random number generator
  -> JWS      -- ^ JWS to sign
  -> Header   -- ^ Header for signature
  -> JWK      -- ^ Key with which to sign
  -> (Either Error JWS, g) -- ^ JWS with new signature appended
signJWS g (JWS p sigs) h k = first (either Left (Right . appendSig)) $
  sign (headerAlg h) k g (BSL.toStrict $ signingInput h p)
  where
    appendSig sig = JWS p (Signature h (Types.Base64Octets sig):sigs)

-- | Verify a JWS.
--
-- Verification succeeds if any signature on the JWS is successfully
-- validated with the given 'Key'.
--
verifyJWS :: JWK -> JWS -> Bool
verifyJWS k (JWS p sigs) = any ((== Right True) . verifySig k p) sigs

verifySig :: JWK -> Types.Base64Octets -> Signature -> Either Error Bool
verifySig k m (Signature h (Types.Base64Octets s))
  = verify (headerAlg h) k (BSL.toStrict $ signingInput h m) s
