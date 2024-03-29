-- Copyright (C) 2016, 2017  Fraser Tweedale
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

{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-|

Types and functions for working with JOSE header parameters.

-}
module Crypto.JOSE.Header
  (
  -- * Constructing header parameters
    HeaderParam(..)
  , newHeaderParamProtected
  , newHeaderParamUnprotected

  -- ** Header protection support
  , ProtectionSupport(..)
  , ProtectionIndicator

  , OptionalProtection(..)
  , RequiredProtection(..)
  , Protection

  , protection
  , isProtected
  , param

  -- * Defining header parsers
  -- $parsing
  , HasParams(..)
  , headerRequired
  , headerRequiredProtected
  , headerOptional
  , headerOptional'
  , headerOptionalProtected

  -- * Parsing headers
  , parseParams
  , parseCrit

  -- * Encoding headers
  , protectedParamsEncoded
  , unprotectedParams


  -- * Header fields shared by JWS and JWE
  , HasAlg(..)
  , HasJku(..)
  , HasJwk(..)
  , HasKid(..)
  , HasX5u(..)
  , HasX5c(..)
  , HasX5t(..)
  , HasX5tS256(..)
  , HasTyp(..)
  , HasCty(..)
  , HasCrit(..)
  ) where


import qualified Control.Monad.Fail as Fail
import Data.Kind (Type)
import Data.List.NonEmpty (NonEmpty)
import Data.Proxy (Proxy(..))

import Control.Lens (Lens', Getter, review, to)
import Data.Aeson (FromJSON(..), Object, Value, encode, object)
import Data.Aeson.Types (Pair, Parser)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as M
import qualified Data.ByteString.Lazy as L
import qualified Data.Text as T

import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import Crypto.JOSE.JWK (JWK)
import Crypto.JOSE.Types.Internal (base64url)
import qualified Crypto.JOSE.Types as Types


-- | A thing with parameters.
--
class HasParams (a :: Type -> Type) where
  -- | Return a list of parameters,
  -- each paired with whether it is protected or not.
  params :: ProtectionSupport p => a p -> [(Bool, Pair)]

  -- | List of "known extensions", i.e. keys that may appear in the
  -- "crit" header parameter.
  extensions :: Proxy a -> [T.Text]
  extensions = const []

  parseParamsFor
    :: (HasParams b, ProtectionSupport p)
    => Proxy b -> Maybe Object -> Maybe Object -> Parser (a p)

-- | Parse a pair of objects (protected and unprotected header)
--
-- This internally invokes 'parseParamsFor' applied to a proxy for
-- the target type.  (This allows the parsing of the "crit" parameter
-- to access "known extensions" understood by the target type.)
--
parseParams
  :: forall a p. (HasParams a, ProtectionSupport p)
  => Maybe Object -- ^ protected header
  -> Maybe Object -- ^ unprotected header
  -> Parser (a p)
parseParams = parseParamsFor (Proxy :: Proxy a)

protectedParams
  :: (HasParams a, ProtectionSupport p)
  => a p -> Maybe Value {- ^ Object -}
protectedParams h =
  case (map snd . filter fst . params) h of
    [] -> Nothing
    xs -> Just (object xs)

-- | Return the base64url-encoded protected parameters
--
protectedParamsEncoded
  :: (HasParams a, ProtectionSupport p)
  => a p -> L.ByteString
protectedParamsEncoded =
  maybe mempty (review base64url . encode) . protectedParams

-- | Return unprotected params as a JSON 'Value' (always an object)
--
unprotectedParams
  :: (HasParams a, ProtectionSupport p)
  => a p -> Maybe Value {- ^ Object -}
unprotectedParams h =
  case (map snd . filter (not . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)


-- | Class that defines the protected and (if supported) unprotected values
-- for a protection indicator data type.
--
class Eq a => ProtectionSupport a where
  -- | Get a value for indicating protection.
  getProtected :: a

  -- | Get a 'Just' a value for indicating no protection, or 'Nothing'
  -- if the type does not support unprotected headers.
  getUnprotected :: Maybe a

type ProtectionIndicator = ProtectionSupport
{-# DEPRECATED ProtectionIndicator "renamed to 'ProtectionSupport." #-}



-- | Use this protection type when the serialisation supports both
-- protected and unprotected headers.
--
data OptionalProtection = Protected | Unprotected
  deriving (Eq, Show)

instance ProtectionSupport OptionalProtection where
  getProtected = Protected
  getUnprotected = Just Unprotected

type Protection = OptionalProtection
{-# DEPRECATED Protection "renamed to 'OptionalProtection'." #-}


-- | Use this protection type when the serialisation only supports
-- protected headers.
--
data RequiredProtection = RequiredProtection
  deriving (Eq, Show)

instance ProtectionSupport RequiredProtection where
  getProtected = RequiredProtection
  getUnprotected = Nothing


-- | A header value, along with a protection indicator.
--
data HeaderParam p a = HeaderParam p a
  deriving (Eq, Show)

instance Functor (HeaderParam p) where
  fmap f (HeaderParam p a) = HeaderParam p (f a)

-- | Lens for the 'Protection' of a 'HeaderParam'
protection :: Lens' (HeaderParam p a) p
protection f (HeaderParam p v) = fmap (\p' -> HeaderParam p' v) (f p)
{-# ANN protection "HLint: ignore Avoid lambda using `infix`" #-}

-- | Lens for a 'HeaderParam' value
param :: Lens' (HeaderParam p a) a
param f (HeaderParam p v) = fmap (\v' -> HeaderParam p v') (f v)
{-# ANN param "HLint: ignore Avoid lambda" #-}

-- | Getter for whether a parameter is protected
isProtected :: (ProtectionSupport p) => Getter (HeaderParam p a) Bool
isProtected = protection . to (== getProtected)


-- | Convenience constructor for a protected 'HeaderParam'.
newHeaderParamProtected :: (ProtectionIndicator p) => a -> HeaderParam p a
newHeaderParamProtected = HeaderParam getProtected

-- | Convenience constructor for a protected 'HeaderParam'.
newHeaderParamUnprotected :: a -> HeaderParam OptionalProtection a
newHeaderParamUnprotected = HeaderParam Unprotected


{- $parsing

The 'parseParamsFor' function defines the parser for a header type.

@
'parseParamsFor'
  :: ('HasParams' a, HasParams b)
  => Proxy b -> Maybe Object -> Maybe Object -> 'Parser' a
@

It is defined over two objects: the /protected header/ and the
/unprotected header/.  The following functions are provided for
parsing header parameters:

['headerOptional']
  An optional parameter that may be protected or unprotected.
['headerRequired']
  A required parameter that may be protected or unprotected.
['headerOptionalProtected']
  An optional parameter that, if present, MUST be carried in the protected header.
['headerRequiredProtected']
  A required parameter that, if present, MUST be carried in the protected header.

Duplicate headers are forbidden.  The above functions all perform
duplicate header detection.  If you do not use them, be sure to
perform this detection yourself!

An example parser:

@
instance HasParams ACMEHeader where
  'parseParamsFor' proxy hp hu = ACMEHeader
    \<$> 'parseParamsFor' proxy hp hu
    \<*> 'headerRequiredProtected' "nonce" hp hu
@

-}

-- | Parse an optional parameter that may be carried in either
-- the protected or the unprotected header.
--
headerOptional
  :: (FromJSON a, ProtectionSupport p)
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe (HeaderParam p a))
headerOptional = headerOptional' parseJSON

-- | Parse an optional parameter that may be carried in either
-- the protected or the unprotected header.  Like 'headerOptional',
-- but with an explicit argument for the parser.
--
headerOptional'
  :: (ProtectionSupport p)
  => (Value -> Parser a)
  -> T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe (HeaderParam p a))
headerOptional' parser kText hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show kText
  (Just v, Nothing)   -> Just . HeaderParam getProtected <$> parser v
  (Nothing, Just v)   -> maybe
    (fail "unprotected header not supported")
    (\p -> Just . HeaderParam p <$> parser v)
    getUnprotected
  (Nothing, Nothing)  -> pure Nothing
  where
    k = Key.fromText kText

-- | Parse an optional parameter that, if present, MUST be carried
-- in the protected header.
--
headerOptionalProtected
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe a)
headerOptionalProtected kText hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show kText
  (_, Just _) -> fail $ "header must be protected: " ++ show kText
  (Just v, _) -> Just <$> parseJSON v
  _           -> pure Nothing
  where
    k = Key.fromText kText

-- | Parse a required parameter that may be carried in either
-- the protected or the unprotected header.
--
headerRequired
  :: (FromJSON a, ProtectionSupport p)
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (HeaderParam p a)
headerRequired kText hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show kText
  (Just v, Nothing)   -> HeaderParam getProtected <$> parseJSON v
  (Nothing, Just v)   -> maybe
    (fail "unprotected header not supported")
    (\p -> HeaderParam p <$> parseJSON v)
    getUnprotected
  (Nothing, Nothing)  -> fail $ "missing required header " ++ show k
  where
    k = Key.fromText kText

-- | Parse a required parameter that MUST be carried
-- in the protected header.
--
headerRequiredProtected
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser a
headerRequiredProtected kText hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show kText
  (_, Just _) -> fail $ "header must be protected: " <> show kText
  (Just v, _) -> parseJSON v
  _           -> fail $ "missing required protected header: " <> show kText
  where
    k = Key.fromText kText


critObjectParser
  :: (Foldable t0, Foldable t1, Fail.MonadFail m)
  => t0 T.Text -> t1 T.Text -> Object -> T.Text -> m T.Text
critObjectParser reserved exts o s
  | s `elem` reserved         = Fail.fail "crit key is reserved"
  | s `notElem` exts          = Fail.fail "crit key is not understood"
  | not (Key.fromText s `M.member` o) = Fail.fail "crit key is not present in headers"
  | otherwise                 = pure s

-- | Parse a "crit" header param
--
-- Fails if:
--
-- * any reserved header appears in "crit" header
-- * any value in "crit" is not a recognised extension
-- * any value in "crit" does not have a corresponding key in the object
--
parseCrit
  :: (Foldable t0, Foldable t1, Traversable t2, Traversable t3, Fail.MonadFail m)
  => t0 T.Text -- ^ reserved header parameters
  -> t1 T.Text -- ^ recognised extensions
  -> Object    -- ^ full header (union of protected and unprotected headers)
  -> t2 (t3 T.Text) -- ^ crit header
  -> m (t2 (t3 T.Text))
parseCrit reserved exts o = mapM (mapM (critObjectParser reserved exts o))
  -- TODO fail on duplicate strings


class HasAlg a where
  alg :: Lens' (a p) (HeaderParam p JWA.JWS.Alg)

class HasJku a where
  jku :: Lens' (a p) (Maybe (HeaderParam p Types.URI))

class HasJwk a where
  jwk :: Lens' (a p) (Maybe (HeaderParam p JWK))

class HasKid a where
  kid :: Lens' (a p) (Maybe (HeaderParam p T.Text))

class HasX5u a where
  x5u :: Lens' (a p) (Maybe (HeaderParam p Types.URI))

class HasX5c a where
  x5c :: Lens' (a p) (Maybe (HeaderParam p (NonEmpty Types.SignedCertificate)))

class HasX5t a where
  x5t :: Lens' (a p) (Maybe (HeaderParam p Types.Base64SHA1))

class HasX5tS256 a where
  x5tS256 :: Lens' (a p) (Maybe (HeaderParam p Types.Base64SHA256))

class HasTyp a where
  typ :: Lens' (a p) (Maybe (HeaderParam p T.Text))

class HasCty a where
  cty :: Lens' (a p) (Maybe (HeaderParam p T.Text))

class HasCrit a where
  crit :: Lens' (a p) (Maybe (NonEmpty T.Text))
