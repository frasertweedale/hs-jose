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

{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-|

Types and functions for working with JOSE header parameters.

-}
module Crypto.JOSE.Header
  (
  -- * Defining header data types
    HeaderParam(..)
  , ProtectionIndicator(..)
  , Protection(..)
  , protection
  , isProtected
  , param

  -- * Defining header parsers
  -- $parsing
  , HasParams(..)
  , headerRequired
  , headerRequiredProtected
  , headerOptional
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
import Data.List.NonEmpty (NonEmpty)
import Data.Monoid ((<>))
import Data.Proxy (Proxy(..))

import Control.Lens (Lens', Getter, review, to)
import Data.Aeson (FromJSON(..), Object, Value, encode, object)
import Data.Aeson.Types (Pair, Parser)
import qualified Data.ByteString.Lazy as L
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T

import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import Crypto.JOSE.JWK (JWK)
import Crypto.JOSE.Types.Orphans ()
import Crypto.JOSE.Types.Internal (base64url)
import qualified Crypto.JOSE.Types as Types


-- | A thing with parameters.
--
class HasParams (a :: * -> *) where
  -- | Return a list of parameters,
  -- each paired with whether it is protected or not.
  params :: ProtectionIndicator p => a p -> [(Bool, Pair)]

  -- | List of "known extensions", i.e. keys that may appear in the
  -- "crit" header parameter.
  extensions :: Proxy a -> [T.Text]
  extensions = const []

  parseParamsFor
    :: (HasParams b, ProtectionIndicator p)
    => Proxy b -> Maybe Object -> Maybe Object -> Parser (a p)

-- | Parse a pair of objects (protected and unprotected header)
--
-- This internally invokes 'parseParamsFor' applied to a proxy for
-- the target type.  (This allows the parsing of the "crit" parameter
-- to access "known extensions" understood by the target type.)
--
parseParams
  :: forall a p. (HasParams a, ProtectionIndicator p)
  => Maybe Object -- ^ protected header
  -> Maybe Object -- ^ unprotected header
  -> Parser (a p)
parseParams = parseParamsFor (Proxy :: Proxy a)

protectedParams
  :: (HasParams a, ProtectionIndicator p)
  => a p -> Maybe Value {- ^ Object -}
protectedParams h =
  case (map snd . filter fst . params) h of
    [] -> Nothing
    xs -> Just (object xs)

-- | Return the base64url-encoded protected parameters
--
protectedParamsEncoded
  :: (HasParams a, ProtectionIndicator p)
  => a p -> L.ByteString
protectedParamsEncoded =
  maybe mempty (review base64url . encode) . protectedParams

-- | Return unprotected params as a JSON 'Value' (always an object)
--
unprotectedParams
  :: (HasParams a, ProtectionIndicator p)
  => a p -> Maybe Value {- ^ Object -}
unprotectedParams h =
  case (map snd . filter (not . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)

-- | Whether a header is protected or unprotected
--
data Protection = Protected | Unprotected
  deriving (Eq, Show)

class Eq a => ProtectionIndicator a where
  -- | Get a value for indicating protection.
  getProtected :: a

  -- | Get a 'Just' a value for indicating no protection, or 'Nothing'
  -- if the type does not support unprotected headers.
  getUnprotected :: Maybe a

instance ProtectionIndicator Protection where
  getProtected = Protected
  getUnprotected = Just Unprotected

instance ProtectionIndicator () where
  getProtected = ()
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

-- | Lens for a 'HeaderParam' value
param :: Lens' (HeaderParam p a) a
param f (HeaderParam p v) = fmap (\v' -> HeaderParam p v') (f v)

-- | Getter for whether a parameter is protected
isProtected :: (ProtectionIndicator p) => Getter (HeaderParam p a) Bool
isProtected = protection . to (== getProtected)


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
  :: (FromJSON a, ProtectionIndicator p)
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe (HeaderParam p a))
headerOptional k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (Just v, Nothing)   -> Just . HeaderParam getProtected <$> parseJSON v
  (Nothing, Just v)   -> maybe
    (fail "unprotected header not supported")
    (\p -> Just . HeaderParam p <$> parseJSON v)
    getUnprotected
  (Nothing, Nothing)  -> pure Nothing

-- | Parse an optional parameter that, if present, MUST be carried
-- in the protected header.
--
headerOptionalProtected
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe a)
headerOptionalProtected k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (_, Just _) -> fail $ "header must be protected: " ++ show k
  (Just v, _) -> Just <$> parseJSON v
  _           -> pure Nothing

-- | Parse a required parameter that may be carried in either
-- the protected or the unprotected header.
--
headerRequired
  :: (FromJSON a, ProtectionIndicator p)
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (HeaderParam p a)
headerRequired k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (Just v, Nothing)   -> HeaderParam getProtected <$> parseJSON v
  (Nothing, Just v)   -> maybe
    (fail "unprotected header not supported")
    (\p -> HeaderParam p <$> parseJSON v)
    getUnprotected
  (Nothing, Nothing)  -> fail $ "missing required header " ++ show k

-- | Parse a required parameter that MUST be carried
-- in the protected header.
--
headerRequiredProtected
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser a
headerRequiredProtected k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (_, Just _) -> fail $ "header must be protected: " <> show k
  (Just v, _) -> parseJSON v
  _           -> fail $ "missing required protected header: " <> show k


critObjectParser
  :: (Foldable t0, Foldable t1, Fail.MonadFail m)
  => t0 T.Text -> t1 T.Text -> Object -> T.Text -> m T.Text
critObjectParser reserved exts o s
  | s `elem` reserved         = Fail.fail "crit key is reserved"
  | s `notElem` exts          = Fail.fail "crit key is not understood"
  | not (s `M.member` o)      = Fail.fail "crit key is not present in headers"
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
