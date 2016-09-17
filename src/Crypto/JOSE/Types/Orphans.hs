-- Copyright (C) 2014, 2015, 2016  Fraser Tweedale
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

{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Crypto.JOSE.Types.Orphans where

import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.Text as T
import Network.URI (URI, parseURI)
import Test.QuickCheck

#if ! MIN_VERSION_aeson(0,11,1)
import Data.Foldable (toList)
import qualified Data.Vector as V
#endif

import Data.Aeson


#if ! MIN_VERSION_aeson(0,11,1)
instance FromJSON a => FromJSON (NonEmpty a) where
  parseJSON = withArray "NonEmpty [a]" $ \v -> case toList v of
    [] -> fail "Non-empty list required"
    (x:xs) -> mapM parseJSON (x :| xs)

instance ToJSON a => ToJSON (NonEmpty a) where
  toJSON = Array . V.fromList . map toJSON . toList
#endif


instance FromJSON URI where
  parseJSON = withText "URI" $
    maybe (fail "not a URI") return . parseURI . T.unpack

instance ToJSON URI where
  toJSON = String . T.pack . show


#if ! MIN_VERSION_QuickCheck(2,9,0)
instance Arbitrary a => Arbitrary (NonEmpty a) where
  arbitrary = (:|) <$> arbitrary <*> arbitrary
#endif
