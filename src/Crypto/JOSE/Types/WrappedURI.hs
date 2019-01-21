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

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.JOSE.Types.WrappedURI where
  
import Control.Lens(Rewrapped, Wrapped(_Wrapped', Unwrapped), _Wrapped, Getting, AReview, iso, view)
import Control.Monad.Error.Lens(throwing)
import Data.Aeson
import Data.Aeson.Types
import Data.Text(Text)
import Crypto.JOSE.Types.Internal
import Control.Monad.Catch(MonadThrow)
import qualified Waargonaut.Encode as Encoder(text)
import Waargonaut.Encode(Encoder)
import qualified Waargonaut.Decode as Decoder(text)
import Waargonaut.Decode(Decoder)
import Waargonaut.Decode.Error(_ConversionFailure)
import Data.Functor.Contravariant(contramap)
import Text.URI (URI, mkURI, render)

newtype WrappedURI =
  WrappedURI URI
  deriving (Eq, Ord, Show)

instance WrappedURI ~ x => Rewrapped WrappedURI x

instance Wrapped WrappedURI where
  type Unwrapped WrappedURI =
    URI
  _Wrapped' =
    iso
      (\(WrappedURI x) -> x)
      WrappedURI

instance FromJSON WrappedURI where
  parseJSON = withText "URI" $
    maybe (fail "not a URI") return . mkURI'

instance ToJSON WrappedURI where
  toJSON = String . render'

encodeURI ::
  Applicative f =>
  Encoder f URI
encodeURI =
  contramap render Encoder.text

encodeWrappedURI ::
  Applicative f =>
  Encoder f WrappedURI
encodeWrappedURI =
  contramap render' Encoder.text

decodeURI ::
  Monad f =>
  Decoder f URI
decodeURI =
  Decoder.text >>= \a -> case mkURI a of
    Nothing ->
      throwing _ConversionFailure a
    Just u ->
      pure u

decodeWrappedURI ::
  Monad f =>
  Decoder f WrappedURI
decodeWrappedURI =
  Decoder.text >>= \a -> case mkURI' a of
    Nothing ->
      throwing _ConversionFailure a
    Just u ->
      pure u

mkURI' ::
  MonadThrow f =>
  Text
  -> f WrappedURI
mkURI' =
  fmap WrappedURI . mkURI

render' ::
  WrappedURI
  -> Text
render' =
  render . view _Wrapped

kvURI :: KeyValue kv => Text -> URI -> kv
kvURI = previewEqual (_Wrapped :: AReview WrappedURI URI)

parseURI :: Object -> Text -> Parser (Maybe URI)
parseURI = viewMaybe (_Wrapped :: Getting URI WrappedURI URI)
