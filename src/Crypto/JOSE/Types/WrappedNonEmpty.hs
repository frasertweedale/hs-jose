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

{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.JOSE.Types.WrappedNonEmpty where

import Data.List.NonEmpty (NonEmpty(..))
import Test.QuickCheck(Arbitrary(arbitrary), Gen)
import Data.Foldable (toList)
import qualified Data.Vector as V(fromList)

import Control.Lens(Rewrapped, Wrapped(_Wrapped', Unwrapped), _Wrapped, Getting, AReview, iso, view)
import Data.Aeson
import Data.Aeson.Types
import Data.Text(Text)
import Crypto.JOSE.Types.Internal
import qualified Waargonaut.Encode as Encoder(nonempty)
import Waargonaut.Encode(Encoder)
import qualified Waargonaut.Decode as Decoder(nonempty)
import Waargonaut.Decode(Decoder)
import Data.Functor.Contravariant(contramap)

newtype WrappedNonEmpty a =
  WrappedNonEmpty (NonEmpty a)
  deriving (Eq, Ord, Show, Functor, Foldable, Traversable)

instance WrappedNonEmpty a ~ x => Rewrapped (WrappedNonEmpty a) x

instance Wrapped (WrappedNonEmpty a) where
  type Unwrapped (WrappedNonEmpty a) =
    NonEmpty a
  _Wrapped' =
    iso
      (\(WrappedNonEmpty x) -> x)
      WrappedNonEmpty

instance FromJSON a => FromJSON (WrappedNonEmpty a) where
  parseJSON =
    withArray "WrappedNonEmpty [a]" $ \v -> case toList v of
      [] -> fail "Wrapped Non-empty list required"
      (x:xs) -> mapM parseJSON (WrappedNonEmpty (x :| xs))

instance ToJSON a => ToJSON (WrappedNonEmpty a) where
  toJSON = Array . V.fromList . map toJSON . toList

instance Arbitrary a => Arbitrary (WrappedNonEmpty a) where
  arbitrary = (\h t -> WrappedNonEmpty (h :| t)) <$> arbitrary <*> arbitrary

encodeWrappedNonEmpty ::
  Applicative f =>
  Encoder f a
  -> Encoder f (WrappedNonEmpty a)
encodeWrappedNonEmpty =
  contramap (view _Wrapped) . Encoder.nonempty

decodeWrappedNonEmpty ::
  Monad f =>
  Decoder f a
  -> Decoder f (WrappedNonEmpty a)
decodeWrappedNonEmpty =
  fmap WrappedNonEmpty . Decoder.nonempty
  
kvNonEmpty :: (ToJSON a, KeyValue kv) => Text -> NonEmpty a -> kv
kvNonEmpty = previewEqual (_Wrapped :: AReview (WrappedNonEmpty a) (NonEmpty a))

parseNonEmpty :: FromJSON a => Object -> Text -> Parser (Maybe (NonEmpty a))
parseNonEmpty = viewMaybe (_Wrapped :: Getting (NonEmpty a) (WrappedNonEmpty a) (NonEmpty a))

gettingGenNonEmpty :: Arbitrary a => Gen (NonEmpty a)
gettingGenNonEmpty = gettingGen (_Wrapped :: Getting (NonEmpty a) (WrappedNonEmpty a) (NonEmpty a))

gettingGenMaybeNonEmpty :: Arbitrary a => Gen (Maybe (NonEmpty a))
gettingGenMaybeNonEmpty = genMaybe gettingGenNonEmpty
