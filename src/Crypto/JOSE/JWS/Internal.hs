-- Copyright (C) 2013, 2014, 2015  Fraser Tweedale
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

import Prelude hiding (mapM)

import Control.Applicative
import Control.Monad ((>=>), when, unless)
import Data.Bifunctor
import Data.Maybe

import Control.Lens ((^.))
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
import Data.HashMap.Strict (member)
import Data.List.NonEmpty (NonEmpty(..), toList)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Traversable (mapM)

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

newtype CritParameters = CritParameters (NonEmpty (T.Text, Value))
  deriving (Eq, Show)

critObjectParser :: Object -> T.Text -> Parser (T.Text, Value)
critObjectParser o s
  | s `elem` critInvalidNames = fail "crit key is reserved"
  | otherwise                 = (\v -> (s, v)) <$> o .: s

parseCrit :: Object -> NonEmpty T.Text -> Parser CritParameters
parseCrit o = fmap CritParameters . mapM (critObjectParser o)
  -- TODO fail on duplicate strings

instance FromJSON CritParameters where
  parseJSON = withObject "crit" $ \o -> o .: "crit" >>= parseCrit o

instance ToJSON CritParameters where
  toJSON (CritParameters m) = object $ ("crit", toJSON $ fmap fst m) : toList m


-- | JWS Header data type.
data JWSHeader = JWSHeader
  { headerAlg :: Maybe JWA.JWS.Alg
  , headerJku :: Maybe Types.URI  -- ^ JWK Set URL
  , headerJwk :: Maybe JWK
  , headerKid :: Maybe String  -- ^ interpretation unspecified
  , headerX5u :: Maybe Types.URI
  , headerX5c :: Maybe (NonEmpty Types.Base64X509)
  , headerX5t :: Maybe Types.Base64SHA1
  , headerX5tS256 :: Maybe Types.Base64SHA256
  , headerTyp :: Maybe String  -- ^ Content Type (of object)
  , headerCty :: Maybe String  -- ^ Content Type (of payload)
  , headerCrit :: Maybe CritParameters
  }
  deriving (Eq, Show)

instance FromArmour T.Text Error JWSHeader where
  parseArmour s =
        first (compactErr "header")
          (B64UL.decode (BSL.fromStrict $ Types.pad $ T.encodeUtf8 s))
        >>= first JSONDecodeError . eitherDecode
    where
    compactErr s' = CompactDecodeError . ((s' ++ " decode failed: ") ++)

instance ToArmour T.Text JWSHeader where
  toArmour = T.decodeUtf8 . Types.unpad . B64U.encode . BSL.toStrict . encode

instance FromJSON JWSHeader where
  parseJSON = withObject "JWS Header" $ \o -> JWSHeader
    <$> o .:? "alg"
    <*> o .:? "jku"
    <*> o .:? "jwk"
    <*> o .:? "kid"
    <*> o .:? "x5u"
    <*> o .:? "x5c"
    <*> o .:? "x5t"
    <*> o .:? "x5t#S256"
    <*> o .:? "typ"
    <*> o .:? "cty"
    <*> (o .:? "crit" >>= mapM (parseCrit o))

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

-- | Construct a minimal header with the given algorithm
--
newJWSHeader :: JWA.JWS.Alg -> JWSHeader
newJWSHeader alg = def { headerAlg = Just alg }


data Signature = Signature
  (Maybe (Armour T.Text JWSHeader))
  (Maybe JWSHeader)
  Types.Base64Octets
  deriving (Eq, Show)

algorithm :: Signature -> Maybe JWA.JWS.Alg
algorithm (Signature h h' _) = (h >>= headerAlg . (^. value)) <|> (h' >>= headerAlg)

checkHeaders :: Signature -> Either Error Signature
checkHeaders sig@(Signature h h' _) = do
  unless (isJust h || isJust h') (Left JWSMissingHeader)
  unless (isJust $ algorithm sig) (Left JWSMissingAlg)
  when (isJust $ h' >>= headerCrit) (Left JWSCritUnprotected)
  when hasDup (Left JWSDuplicateHeaderParameter)
  return sig
  where
    isDup f = isJust (h >>= f . (^. value)) && isJust (h' >>= f)
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
      maybe [] (Types.objectPairs . toJSON . (^. value)) h
      ++ maybe [] (Types.objectPairs . toJSON) h'


-- | JSON Web Signature data type.  Consists of a payload and a
-- (possibly empty) list of signatures.
--
data JWS = JWS Types.Base64Octets [Signature]
  deriving (Eq, Show)

instance FromJSON JWS where
  parseJSON v =
    withObject "JWS JSON serialization" (\o -> JWS
      <$> o .: "payload"
      <*> o .: "signatures") v
    <|> withObject "Flattened JWS JSON serialization" (\o ->
      if member "signatures" o
      then fail "\"signatures\" member MUST NOT be present"
      else (\p s -> JWS p [s]) <$> o .: "payload" <*> parseJSON v) v

instance ToJSON JWS where
  toJSON (JWS p ss) = object ["payload" .= p, "signatures" .= ss]

-- | Construct a new (unsigned) JWS
--
newJWS :: BS.ByteString -> JWS
newJWS msg = JWS (Types.Base64Octets msg) []

-- | Payload of a JWS, as a lazy bytestring.
--
jwsPayload :: JWS -> BSL.ByteString
jwsPayload (JWS (Types.Base64Octets s) _) = BSL.fromStrict s

signingInput :: Maybe (Armour T.Text JWSHeader) -> Types.Base64Octets -> BS.ByteString
signingInput h p = BS.intercalate "."
  [ maybe "" (T.encodeUtf8 . (^. armour)) h
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
    xs' -> Left $ compactErr "compact representation"
      $ "expected 3 parts, got " ++ show (length xs')
    where
      compactErr s = CompactDecodeError . ((s ++ " decode failed: ") ++)
      decodeS desc s =
        first (compactErr desc)
          (A.eitherResult $ A.parse P.value $ BSL.intercalate s ["\"", "\""])
        >>= first JSONDecodeError . parseEither parseJSON


-- §5.1. Message Signing or MACing

-- | Create a new signature on a JWS.
--
signJWS
  :: MonadRandom m
  => JWS      -- ^ JWS to sign
  -> JWSHeader  -- ^ Header for signature
  -> JWK      -- ^ Key with which to sign
  -> m (Either Error JWS) -- ^ JWS with new signature appended
signJWS (JWS p sigs) h k = case headerAlg h of
    Nothing   -> return $ Left JWSMissingAlg
    Just alg  -> fmap appendSig <$> sign alg (k ^. jwkMaterial) (signingInput h' p)
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
  (\alg -> verify alg (k ^. jwkMaterial) (signingInput h m) s)
  (algorithm sig)
