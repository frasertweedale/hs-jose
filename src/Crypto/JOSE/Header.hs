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
  ) where


import Data.Proxy (Proxy(..))

import Data.Aeson (FromJSON(..), Object, Value, encode, object)
import Data.Aeson.Types (Pair, Parser)
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.ByteString.Lazy as L
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T

import Crypto.JOSE.Types.Orphans ()
import Crypto.JOSE.Types.Internal (unpad)


class HasParams a where
  params :: a -> [(Protection, Pair)]

  extensions :: Proxy a -> [T.Text]
  extensions = const []

  parseParamsFor :: HasParams b => Proxy b -> Maybe Object -> Maybe Object -> Parser a

parseParams :: forall a. HasParams a => Maybe Object -> Maybe Object -> Parser a
parseParams = parseParamsFor (Proxy :: Proxy a)

protectedParams :: HasParams a => a -> Maybe Value {- ^ Object -}
protectedParams h =
  case (map snd . filter ((== Protected) . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)

protectedParamsEncoded :: HasParams a => a -> L.ByteString
protectedParamsEncoded =
  maybe mempty (unpad . B64UL.encode . encode) . protectedParams

unprotectedParams :: HasParams a => a -> Maybe Value {- ^ Object -}
unprotectedParams h =
  case (map snd . filter ((== Unprotected) . fst) . params) h of
    [] -> Nothing
    xs -> Just (object xs)


data Protection = Protected | Unprotected
  deriving (Eq, Show)

data HeaderParam a = HeaderParam Protection a
  deriving (Eq, Show)

protection :: HeaderParam a -> Protection
protection (HeaderParam b _) = b

param :: HeaderParam a -> a
param (HeaderParam _ a) = a


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

parseCrit
  :: (Foldable t0, Foldable t1, Traversable t2, Traversable t3, Monad m)
  => t0 T.Text
  -> t1 T.Text
  -> Object
  -> t2 (t3 T.Text)
  -> m (t2 (t3 T.Text))
parseCrit reserved exts o = mapM (mapM (critObjectParser reserved exts o))
  -- TODO fail on duplicate strings
