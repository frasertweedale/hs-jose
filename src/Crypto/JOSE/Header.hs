-- Copyright (C) 2016  Fraser Tweedale
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

{-# LANGUAGE ScopedTypeVariables #-}

{-|

Types and functions for working with JOSE header parameters.

-}
module Crypto.JOSE.Header
  (
    HasParams(..)
  , parseParams
  , protectedParamsEncoded
  , unprotectedParams

  , parseCrit

  , Protection(..)
  , HeaderParam(..)
  , protection
  , param
  , headerRequired
  , headerOptional
  , headerOptionalProtected

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


import Data.List.NonEmpty (NonEmpty)
import Data.Proxy (Proxy(..))

import Control.Lens (Lens')
import Data.Aeson (FromJSON(..), Object, Value, encode, object)
import Data.Aeson.Types (Pair, Parser)
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.ByteString.Lazy as L
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T

import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import Crypto.JOSE.JWK (JWK)
import Crypto.JOSE.Types.Orphans ()
import Crypto.JOSE.Types.Internal (unpad)
import qualified Crypto.JOSE.Types as Types


-- | A thing with parameters.  Parameters may be 'Protected' or 'Unprotected'
--
class HasParams a where
  params :: a -> [(Protection, Pair)]

  -- | List of "known extensions", i.e. keys that may appear in the
  -- "crit" header parameter.
  extensions :: Proxy a -> [T.Text]
  extensions = const []

  parseParamsFor :: HasParams b => Proxy b -> Maybe Object -> Maybe Object -> Parser a

-- | Parse a pair of objects (protected and unprotected header)
--
parseParams
  :: forall a. HasParams a
  => Maybe Object -- ^ protected header
  -> Maybe Object -- ^ unprotected header
  -> Parser a
parseParams = parseParamsFor (Proxy :: Proxy a)

protectedParams :: HasParams a => a -> Maybe Value {- ^ Object -}
protectedParams h =
  case (map snd . filter ((== Protected) . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)

-- | Return the encoded protected parameters
--
protectedParamsEncoded :: HasParams a => a -> L.ByteString
protectedParamsEncoded =
  maybe mempty (unpad . B64UL.encode . encode) . protectedParams

-- | Return unprotected params as a JSON 'Value' (always an object)
--
unprotectedParams :: HasParams a => a -> Maybe Value {- ^ Object -}
unprotectedParams h =
  case (map snd . filter ((== Unprotected) . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)

-- | Whether a header is protected or unprotected
--
data Protection = Protected | Unprotected
  deriving (Eq, Show)

-- | A header value, along with whether it was (or will be) encoded
-- in the protected header
--
data HeaderParam a = HeaderParam Protection a
  deriving (Eq, Show)

-- | Lens for the 'Protection' of a 'HeaderParam'
protection :: Lens' (HeaderParam a) Protection
protection f (HeaderParam p v) = fmap (\p' -> HeaderParam p' v) (f p)

-- | Lens for a 'HeaderParam' value
param :: Lens' (HeaderParam a) a
param f (HeaderParam p v) = fmap (\v' -> HeaderParam p v') (f v)


-- | Parse an optional parameter that may be carried in either
-- the protected or the unprotected header.
--
headerOptional
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (Maybe (HeaderParam a))
headerOptional k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (Just v, Nothing)   -> Just . HeaderParam Protected <$> parseJSON v
  (Nothing, Just v)   -> Just . HeaderParam Unprotected <$> parseJSON v
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
  (_, Just _) -> fail $ "header must be protected: " ++ show k
  (Just v, _) -> Just <$> parseJSON v
  _           -> pure Nothing

-- | Parse a required parameter that may be carried in either
-- the protected or the unprotected header.
--
headerRequired
  :: FromJSON a
  => T.Text
  -> Maybe Object
  -> Maybe Object
  -> Parser (HeaderParam a)
headerRequired k hp hu = case (hp >>= M.lookup k, hu >>= M.lookup k) of
  (Just _, Just _)    -> fail $ "duplicate header " ++ show k
  (Just v, Nothing)   -> HeaderParam Protected <$> parseJSON v
  (Nothing, Just v)   -> HeaderParam Unprotected <$> parseJSON v
  (Nothing, Nothing)  -> fail $ "missing required header " ++ show k


critObjectParser
  :: (Foldable t0, Foldable t1, Monad m)
  => t0 T.Text -> t1 T.Text -> Object -> T.Text -> m T.Text
critObjectParser reserved exts o s
  | s `elem` reserved         = fail "crit key is reserved"
  | s `notElem` exts          = fail "crit key is not understood"
  | not (s `M.member` o)      = fail "crit key is not present in headers"
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
  :: (Foldable t0, Foldable t1, Traversable t2, Traversable t3, Monad m)
  => t0 T.Text -- ^ reserved header parameters
  -> t1 T.Text -- ^ recognised extensions
  -> Object    -- ^ full header (union of protected and unprotected headers)
  -> t2 (t3 T.Text) -- ^ crit header
  -> m (t2 (t3 T.Text))
parseCrit reserved exts o = mapM (mapM (critObjectParser reserved exts o))
  -- TODO fail on duplicate strings


class HasAlg a where
  alg :: Lens' a (HeaderParam JWA.JWS.Alg)

class HasJku a where
  jku :: Lens' a (Maybe (HeaderParam Types.URI))

class HasJwk a where
  jwk :: Lens' a (Maybe (HeaderParam JWK))

class HasKid a where
  kid :: Lens' a (Maybe (HeaderParam String))

class HasX5u a where
  x5u :: Lens' a (Maybe (HeaderParam Types.URI))

class HasX5c a where
  x5c :: Lens' a (Maybe (HeaderParam (NonEmpty Types.Base64X509)))

class HasX5t a where
  x5t :: Lens' a (Maybe (HeaderParam Types.Base64SHA1))

class HasX5tS256 a where
  x5tS256 :: Lens' a (Maybe (HeaderParam Types.Base64SHA256))

class HasTyp a where
  typ :: Lens' a (Maybe (HeaderParam String))

class HasCty a where
  cty :: Lens' a (Maybe (HeaderParam String))

class HasCrit a where
  crit :: Lens' a (Maybe (NonEmpty T.Text))
