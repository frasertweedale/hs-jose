-- Copyright (C) 2013, 2014, 2015, 2016  Fraser Tweedale
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
{-# LANGUAGE TemplateHaskell #-}

{-|

Data types for the JOSE library.

-}
module Crypto.JOSE.Types
  (
    Base64Integer(..)
  , _Base64Integer
  , SizedBase64Integer(..)
  , genSizedBase64IntegerOf
  , checkSize
  , Base64Octets(..)
  , Base64SHA1(..)
  , Base64SHA256(..)
  , Base64X509(..)
  , SignedCertificate
  , URI
  , base64url
  ) where

import Data.Word (Word8)

import Control.Lens
import Data.Aeson
import Data.Aeson.Types (Parser)
import qualified Data.ByteString as B
import Data.X509
import Network.URI (URI)
import Test.QuickCheck
import Test.QuickCheck.Instances ()

import Crypto.Number.Basic (log2)
import Crypto.JOSE.Types.Internal
import Crypto.JOSE.Types.Orphans ()


-- | A base64url encoded octet sequence interpreted as an integer.
--
-- The value is encoded in the minimum number of octets (no leading
-- zeros) with the exception of @0@ which is encoded as @AA@.
-- A leading zero when decoding is an error.
--
newtype Base64Integer = Base64Integer Integer
  deriving (Eq, Show)
makePrisms ''Base64Integer

instance FromJSON Base64Integer where
  parseJSON = withText "base64url integer" $ parseB64Url
    (fmap Base64Integer . parseOctets)

-- | Parse an octet sequence into an integer.
--
-- This function deals with ugly special cases from
-- <https://tools.ietf.org/html/rfc7518#section-2>, specifically
--
-- * The empty sequence is invalid
-- * Leading null byte is invalid (unless it is the only byte)
--
parseOctets :: B.ByteString -> Parser Integer
parseOctets s
  | B.null s      = fail "empty octet sequence"
  | s == "\NUL"   = pure 0
  | B.head s == 0 = fail "leading null byte"
  | otherwise     = pure (bsToInteger s)

instance ToJSON Base64Integer where
  -- Urgh, special case: https://tools.ietf.org/html/rfc7518#section-2
  toJSON (Base64Integer 0) = "AA"
  toJSON (Base64Integer x) = encodeB64Url $ integerToBS x


arbitraryBigInteger :: Gen Integer
arbitraryBigInteger = do
  size <- arbitrarySizedNatural  -- number of octets
  go (size + 1) 0
  where
    go :: Integer -> Integer -> Gen Integer
    go 0 n = pure n
    go k n =
      (n * 256 +) . fromIntegral <$> (arbitraryBoundedIntegral :: Gen Word8)
      >>= go (k - 1)


instance Arbitrary Base64Integer where
  arbitrary = Base64Integer <$> arbitraryBigInteger


-- | A base64url encoded octet sequence interpreted as an integer
-- and where the number of octets carries explicit bit-length
-- information.
--
data SizedBase64Integer = SizedBase64Integer Int Integer
  deriving (Show)

instance Eq SizedBase64Integer where
  SizedBase64Integer _ n == SizedBase64Integer _ m = n == m

instance Arbitrary SizedBase64Integer where
  arbitrary = do
    x <- arbitraryBigInteger
    l <- Test.QuickCheck.elements [0,1,2]  -- number of leading zero-bytes
    pure $ SizedBase64Integer ((log2 x `div` 8) + 1 + l) x

genByteStringOf :: Int -> Gen B.ByteString
genByteStringOf n = B.pack <$> vectorOf n arbitrary

-- | Generate a 'SizedBase64Integer' of the given number of bytes
--
genSizedBase64IntegerOf :: Int -> Gen SizedBase64Integer
genSizedBase64IntegerOf n =
  SizedBase64Integer n . bsToInteger <$> genByteStringOf n

instance FromJSON SizedBase64Integer where
  parseJSON = withText "full size base64url integer" $ parseB64Url (\bytes ->
    pure $ SizedBase64Integer (B.length bytes) (bsToInteger bytes))

instance ToJSON SizedBase64Integer where
  toJSON (SizedBase64Integer w n) = encodeB64Url $ sizedIntegerToBS w n

-- | Parsed a 'SizedBase64Integer' with an expected number of /bytes/.
--
checkSize :: Int -> SizedBase64Integer -> Parser SizedBase64Integer
checkSize n a@(SizedBase64Integer m _) = if n == m
  then return a
  else fail $ "expected " ++ show n ++ " octets, found " ++ show m


-- | A base64url encoded octet sequence.  Used for payloads,
-- signatures, symmetric keys, salts, initialisation vectors, etc.
--
newtype Base64Octets = Base64Octets B.ByteString
  deriving (Eq, Show)

instance FromJSON Base64Octets where
  parseJSON = withText "Base64Octets" $ parseB64Url (pure . Base64Octets)

instance ToJSON Base64Octets where
  toJSON (Base64Octets bytes) = encodeB64Url bytes

instance Arbitrary Base64Octets where
  arbitrary = Base64Octets <$> arbitrary


-- | A base64url encoded SHA-1 digest.  Used for X.509 certificate
-- thumbprints.
--
newtype Base64SHA1 = Base64SHA1 B.ByteString
  deriving (Eq, Show)

instance FromJSON Base64SHA1 where
  parseJSON = withText "base64url SHA-1" $ parseB64Url (\bytes ->
    case B.length bytes of
      20 -> pure $ Base64SHA1 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA1 where
  toJSON (Base64SHA1 bytes) = encodeB64Url bytes

instance Arbitrary Base64SHA1 where
  arbitrary = Base64SHA1 <$> genByteStringOf 20


-- | A base64url encoded SHA-256 digest.  Used for X.509 certificate
-- thumbprints.
--
newtype Base64SHA256 = Base64SHA256 B.ByteString
  deriving (Eq, Show)

instance FromJSON Base64SHA256 where
  parseJSON = withText "base64url SHA-256" $ parseB64Url (\bytes ->
    case B.length bytes of
      32 -> pure $ Base64SHA256 bytes
      _  -> fail "incorrect number of bytes")

instance ToJSON Base64SHA256 where
  toJSON (Base64SHA256 bytes) = encodeB64Url bytes

instance Arbitrary Base64SHA256 where
  arbitrary = Base64SHA256 <$> genByteStringOf 32


-- | A base64 encoded X.509 certificate.
--
newtype Base64X509 = Base64X509 SignedCertificate
  deriving (Eq, Show)

instance FromJSON Base64X509 where
  parseJSON = withText "base64url X.509 certificate" $ parseB64 $
    either fail (pure . Base64X509) . decodeSignedCertificate

instance ToJSON Base64X509 where
  toJSON (Base64X509 x509) = encodeB64 $ encodeSignedObject x509
