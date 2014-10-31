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

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_HADDOCK hide #-}

module Crypto.JOSE.JWS.Internal where

import Control.Applicative
import Control.Arrow
import Control.Monad ((>=>), when, unless)
import Data.Char
import Data.Maybe

import Data.Aeson
import qualified Data.Aeson.Parser as P
import Data.Aeson.Types
import qualified Data.Attoparsec.ByteString.Lazy as A
import Data.Byteable
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import Data.Default.Class
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Traversable (sequenceA)
import qualified Data.Vector as V

import Crypto.JOSE.Classes
import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import Crypto.JOSE.JWK
import qualified Crypto.JOSE.Types as Types
import qualified Crypto.JOSE.Types.Internal as Types
import Crypto.JOSE.Types.Armour


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
data JWSHeader = JWSHeader
  { headerAlg :: Maybe JWA.JWS.Alg
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
  }
  deriving (Eq, Show)

instance FromArmour T.Text Error JWSHeader where
  parseArmour s =
        either (compactErr "header") Right (B64UL.decode (pad $ BSL.fromStrict $ T.encodeUtf8 s))
        >>= either jsonErr Right . eitherDecode
    where
    compactErr s' = Left . CompactDecodeError . ((s' ++ " decode failed: ") ++)
    jsonErr = Left . JSONDecodeError
    pad t = t `BSL.append` BSL.replicate ((4 - BSL.length t `mod` 4) `mod` 4) c
    c = fromIntegral $ ord '='

instance ToArmour T.Text JWSHeader where
  toArmour = T.decodeUtf8 . Types.unpad . B64U.encode . BSL.toStrict . encode

instance FromJSON JWSHeader where
  parseJSON = withObject "JWS Header" $ \o -> JWSHeader
    <$> o .:? "alg"
    <*> o .:? "jku"
    <*> o .:? "jwk"
    <*> o .:? "kid"
    <*> o .:? "x5u"
    <*> o .:? "x5t"
    <*> o .:? "x5t#S256"
    <*> o .:? "x5c"
    <*> o .:? "typ"
    <*> o .:? "cty"
    <*> if M.member "crit" o
      then Just <$> parseJSON (Object o)
      else pure Nothing

instance ToJSON JWSHeader where
  toJSON (JWSHeader alg jku jwk kid x5u x5c x5t x5tS256 typ cty crit) =
    object $ catMaybes
      [ Just ("alg" .= alg)
      , fmap ("jku" .=) jku
      , fmap ("jwk" .=) jwk
      , fmap ("kid" .=) kid
      , fmap ("x5u" .=) x5u
      , fmap ("x5c" .=) x5c
      , fmap ("x5t" .=) x5t
      , fmap ("x5t#S256" .=) x5tS256
      , fmap ("typ" .=) typ
      , fmap ("cty" .=) cty
      ] ++ Types.objectPairs (toJSON crit)

instance Default JWSHeader where
  def = JWSHeader z z z z z z z z z z z where z = Nothing

-- construct a minimal header with the given alg
algHeader :: JWA.JWS.Alg -> JWSHeader
algHeader alg = def { headerAlg = Just alg }


data Signature = Signature
  (Maybe (Armour T.Text JWSHeader))
  (Maybe JWSHeader)
  Types.Base64Octets
  deriving (Eq, Show)

algorithm :: Signature -> Maybe JWA.JWS.Alg
algorithm (Signature h h' _) = (h >>= headerAlg . value) <|> (h' >>= headerAlg)

checkHeaders :: Signature -> Either Error Signature
checkHeaders sig@(Signature h h' _) = do
  unless (isJust h || isJust h') (Left JWSMissingHeader)
  unless (isJust $ algorithm sig) (Left JWSMissingAlg)
  when (isJust $ h' >>= headerCrit) (Left JWSCritUnprotected)
  when hasDup (Left JWSDuplicateHeaderParameter)
  return sig
  where
    isDup f = isJust (h >>= f . value) && isJust (h' >>= f)
    hasDup = or
      [ isDup headerAlg, isDup headerJku, isDup headerJwk
      , isDup headerKid, isDup headerX5u, isDup headerX5c
      , isDup headerX5t, isDup headerX5tS256, isDup headerTyp
      , isDup headerCty
      ]

instance FromJSON Signature where
  parseJSON =
    withObject "signature" (\o -> Signature
      <$> o .:? "protected"
      <*> o .:? "header"
      <*> o .: "signature"
    ) >=> either (fail . show) pure . checkHeaders

instance ToJSON Signature where
  toJSON (Signature h h' s) =
    object $ ("signature" .= s) :
      maybe [] (Types.objectPairs . toJSON . value) h
      ++ maybe [] (Types.objectPairs . toJSON) h'


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

signingInput :: Maybe (Armour T.Text JWSHeader) -> Types.Base64Octets -> BS.ByteString
signingInput h p = BS.intercalate "."
  [ maybe "" (T.encodeUtf8 . armour) h
  , toBytes p
  ]

-- Convert JWS to compact serialization.
--
-- The operation is defined only when there is exactly one
-- signature and returns Nothing otherwise
--
instance ToCompact JWS where
  toCompact (JWS p [Signature h _ s]) =
    Right [BSL.fromStrict $ signingInput h p, BSL.fromStrict $ toBytes s]
  toCompact (JWS _ xs) = Left $ CompactEncodeError $
    "cannot compact serialize JWS with " ++ show (length xs) ++ " sigs"

instance FromCompact JWS where
  fromCompact xs = case xs of
    [h, p, s] -> do
      h' <- decodeArmour $ T.decodeUtf8 $ BSL.toStrict h
      p' <- decodeS "payload" p
      s' <- decodeS "signature" s
      return $ JWS p' [Signature (Just h') Nothing s']
    xs' -> compactErr "compact representation"
      $ "expected 3 parts, got " ++ show (length xs')
    where
      compactErr s = Left . CompactDecodeError . ((s ++ " decode failed: ") ++)
      jsonErr = Left . JSONDecodeError
      decodeS desc s =
        either (compactErr desc) Right
          (A.eitherResult $ A.parse P.value $ BSL.intercalate s ["\"", "\""])
        >>= either jsonErr Right . parseEither parseJSON


-- §5.1. Message Signing or MACing

-- | Create a new signature on a JWS.
--
signJWS
  :: CPRG g
  => g        -- ^ Random number generator
  -> JWS      -- ^ JWS to sign
  -> JWSHeader  -- ^ Header for signature
  -> JWK      -- ^ Key with which to sign
  -> (Either Error JWS, g) -- ^ JWS with new signature appended
signJWS g (JWS p sigs) h k = first (either Left (Right . appendSig)) $
  case headerAlg h of
    Nothing   -> (Left JWSMissingAlg, g)
    Just alg  -> sign alg k g (signingInput h' p)
  where
    appendSig sig = JWS p (Signature h' Nothing (Types.Base64Octets sig):sigs)
    h' = Just $ Unarmoured h


-- | Algorithms for which validation will be attempted.  The default
-- value includes all algorithms except 'None'.
--
newtype ValidationAlgorithms = ValidationAlgorithms [JWA.JWS.Alg]

instance Default ValidationAlgorithms where
  def = ValidationAlgorithms
    [ JWA.JWS.HS256, JWA.JWS.HS384, JWA.JWS.HS512
    , JWA.JWS.RS256, JWA.JWS.RS384, JWA.JWS.RS512
    , JWA.JWS.ES256, JWA.JWS.ES384, JWA.JWS.ES512
    , JWA.JWS.PS256, JWA.JWS.PS384, JWA.JWS.PS512
    ]

-- | Validation policy.  The default policy is 'AllValidated'.
--
data ValidationPolicy
  = AnyValidated
  -- ^ One successfully validated signature is sufficient
  | AllValidated
  -- ^ All signatures for which validation is attempted must be validated

instance Default ValidationPolicy where
  def = AllValidated


-- | Verify a JWS.
--
-- Verification succeeds if any signature on the JWS is successfully
-- validated with the given 'Key'.
--
-- If only specific signatures need to be validated, and the
-- 'ValidationPolicy' argument is not enough to express this,
-- the caller is responsible for removing irrelevant signatures
-- prior to calling 'verifyJWS'.
--
verifyJWS
  :: ValidationAlgorithms
  -> ValidationPolicy
  -> JWK
  -> JWS
  -> Bool
verifyJWS (ValidationAlgorithms algs) policy k (JWS p sigs) =
  applyPolicy policy $ map validate $ filter shouldValidateSig sigs
  where
  shouldValidateSig = maybe False (`elem` algs) . algorithm
  applyPolicy AnyValidated xs = or xs
  applyPolicy AllValidated [] = False
  applyPolicy AllValidated xs = and xs
  validate = (== Right True) . verifySig k p

verifySig :: JWK -> Types.Base64Octets -> Signature -> Either Error Bool
verifySig k m sig@(Signature h _ (Types.Base64Octets s)) = maybe
  (Left $ AlgorithmMismatch "No 'alg' header")  -- shouldn't happen
  (\alg -> verify alg k (signingInput h m) s)
  (algorithm sig)
