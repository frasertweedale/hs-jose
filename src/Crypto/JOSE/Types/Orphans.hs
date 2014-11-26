-- Copyright (C) 2014  Fraser Tweedale
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

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Crypto.JOSE.Types.Orphans where

import qualified Data.Traversable as T
import Data.List.NonEmpty (NonEmpty(..), toList)

import Data.Aeson

import qualified Data.Vector as V

instance FromJSON a => FromJSON (NonEmpty a) where
  parseJSON = withArray "NonEmpty [a]" $ \v -> case V.toList v of
    [] -> fail "Non-empty list required"
    (x:xs) -> T.mapM parseJSON (x :| xs)

instance ToJSON a => ToJSON (NonEmpty a) where
  toJSON = Array . V.fromList . map toJSON . toList
