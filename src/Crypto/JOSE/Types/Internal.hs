-- Copyright (C) 2013, 2014, 2017  Fraser Tweedale
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

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}

{-|

Internal utility functions for encoding/decoding JOSE types.

-}
module Crypto.JOSE.Types.Internal
  (
    objectPairs
  , encodeB64
  , parseB64
  , encodeB64Url
  , parseB64Url
  , bsToInteger
  , integerToBS
  , intBytes
  , sizedIntegerToBS
  , base64url
  ) where

import Data.Bifunctor (first)
import Data.Monoid ((<>))
import Data.Tuple (swap)
import Data.Word (Word8)

import Control.Lens
import Control.Lens.Cons.Extras
import Crypto.Number.Basic (log2)
import Data.Aeson.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as E

-- | Convert a JSON object into a list of pairs or the empty list
-- if the JSON value is not an object.
--
objectPairs :: Value -> [Pair]
objectPairs (Object o) = M.toList o
objectPairs _ = []

-- | Produce a parser of base64 encoded text from a bytestring parser.
--
parseB64 :: (B.ByteString -> Parser a) -> T.Text -> Parser a
parseB64 f = either fail f . decodeB64
  where
    decodeB64 = B64.decode . E.encodeUtf8

-- | Convert a bytestring to a base64 encoded JSON 'String'
--
encodeB64 :: B.ByteString -> Value
encodeB64 = String . E.decodeUtf8 . B64.encode


-- | Prism for encoding / decoding base64url.
--
-- To encode, @'review' base64url@.
-- To decode, @'preview' base64url@.
--
-- Works with any combinations of strict/lazy @ByteString@.
--
base64url ::
  ( AsEmpty s1, AsEmpty s2
  , Cons s1 s1 Word8 Word8
  , Cons s2 s2 Word8 Word8
  ) => Prism' s1 s2
base64url = reconsIso . b64u . reconsIso
  where
    b64u = prism B64U.encodeUnpadded (\s -> first (const s) (B64U.decodeUnpadded s))
    reconsIso = iso (view recons) (view recons)


-- | Produce a parser of base64url encoded text from a bytestring parser.
--
parseB64Url :: (B.ByteString -> Parser a) -> T.Text -> Parser a
parseB64Url f = maybe (fail "Not valid base64url") f . preview base64url . E.encodeUtf8

-- | Convert a bytestring to a base64url encoded JSON 'String'
--
encodeB64Url :: B.ByteString -> Value
encodeB64Url = String . E.decodeUtf8 . review base64url

-- | Convert an unsigned big endian octet sequence to the integer
-- it represents.
--
bsToInteger :: B.ByteString -> Integer
bsToInteger = B.foldl (\acc x -> acc * 256 + toInteger x) 0

-- | Convert an integer to its unsigned big endian representation as
-- an octet sequence.
--
integerToBS :: Integral a => a -> B.ByteString
integerToBS = B.reverse . B.unfoldr (fmap swap . f)
  where
    f 0 = Nothing
    f x = Just (fromIntegral <$> quotRem x 256)

sizedIntegerToBS :: Integral a => Int -> a -> B.ByteString
sizedIntegerToBS w = zeroPad . integerToBS
  where zeroPad xs = B.replicate (w - B.length xs) 0 `B.append` xs

intBytes :: Integer -> Int
intBytes n = (log2 n `div` 8) + 1
