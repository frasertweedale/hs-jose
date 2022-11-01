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

{-|

JWS, JWE and some related specifications provide for "compact"
representations of certain types.  This module defines classes and
functions for working with such data.

-}
module Crypto.JOSE.Compact
  ( FromCompact(..)
  , decodeCompact
  , ToCompact(..)
  , encodeCompact
  ) where

import Control.Monad.Except (MonadError)
import qualified Data.ByteString.Lazy as L

import Crypto.JOSE.Error (AsError)


-- | Data that can be parsed from a compact representation.
--
class FromCompact a where
  fromCompact :: (AsError e, MonadError e m) => [L.ByteString] -> m a

-- | Decode a compact representation.
--
decodeCompact :: (FromCompact a, AsError e, MonadError e m) => L.ByteString -> m a
decodeCompact = fromCompact . L.split 46


-- | Data that can be converted to a compact representation.
--
class ToCompact a where
  toCompact :: a -> [L.ByteString]

-- | Encode data to a compact representation.
--
encodeCompact :: (ToCompact a) => a -> L.ByteString
encodeCompact = L.intercalate "." . toCompact
