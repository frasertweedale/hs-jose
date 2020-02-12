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

{-# LANGUAGE TemplateHaskell #-}

{-|

JOSE error types.

-}
module Crypto.JOSE.Error
  (
    Error(..)
  , AsError(..)

  -- * JOSE compact serialisation errors
  , InvalidNumberOfParts(..), expectedParts, actualParts
  , CompactTextError(..)
  , CompactDecodeError(..)
  , _CompactInvalidNumberOfParts
  , _CompactInvalidText
  ) where

import Data.Semigroup ((<>))
import Numeric.Natural

import qualified Crypto.PubKey.RSA as RSA
import Crypto.Error (CryptoError)
import Control.Lens (Getter, to)
import Control.Lens.TH (makeClassyPrisms, makePrisms)
import qualified Data.Text as T
import qualified Data.Text.Encoding.Error as T


-- | The wrong number of parts were found when decoding a
-- compact JOSE object.
--
data InvalidNumberOfParts =
  InvalidNumberOfParts Natural Natural -- ^ expected vs actual parts
  deriving (Eq)

instance Show InvalidNumberOfParts where
  show (InvalidNumberOfParts n m) =
    "Expected " <> show n <> " parts; got " <> show m

-- | Get the expected or actual number of parts.
expectedParts, actualParts :: Getter InvalidNumberOfParts Natural
expectedParts = to $ \(InvalidNumberOfParts n _) -> n
actualParts   = to $ \(InvalidNumberOfParts _ n) -> n


-- | Bad UTF-8 data in a compact object, at the specified index
data CompactTextError = CompactTextError
  Natural
  T.UnicodeException
  deriving (Eq)

instance Show CompactTextError where
  show (CompactTextError n s) =
    "Invalid text at part " <> show n <> ": " <> show s


-- | An error when decoding a JOSE compact object.
-- JSON decoding errors that occur during compact object processing
-- throw 'JSONDecodeError'.
--
data CompactDecodeError
  = CompactInvalidNumberOfParts InvalidNumberOfParts
  | CompactInvalidText CompactTextError
  deriving (Eq)
makePrisms ''CompactDecodeError

instance Show CompactDecodeError where
  show (CompactInvalidNumberOfParts e) = "Invalid number of parts: " <> show e
  show (CompactInvalidText e) = "Invalid text: " <> show e



-- | All the errors that can occur.
--
data Error
  = AlgorithmNotImplemented   -- ^ A requested algorithm is not implemented
  | AlgorithmMismatch String  -- ^ A requested algorithm cannot be used
  | KeyMismatch T.Text        -- ^ Wrong type of key was given
  | KeySizeTooSmall           -- ^ Key size is too small
  | OtherPrimesNotSupported   -- ^ RSA private key with >2 primes not supported
  | RSAError RSA.Error        -- ^ RSA encryption, decryption or signing error
  | CryptoError CryptoError   -- ^ Various cryptonite library error cases
  | CompactDecodeError CompactDecodeError
  -- ^ Wrong number of parts in compact serialisation
  | JSONDecodeError String    -- ^ JSON (Aeson) decoding error
  | NoUsableKeys              -- ^ No usable keys were found in the key store
  | JWSCritUnprotected
  | JWSNoValidSignatures
  -- ^ 'AnyValidated' policy active, and no valid signature encountered
  | JWSInvalidSignature
  -- ^ 'AllValidated' policy active, and invalid signature encountered
  | JWSNoSignatures
  -- ^ 'AllValidated' policy active, and there were no signatures on object
  --   that matched the allowed algorithms
  deriving (Eq, Show)
makeClassyPrisms ''Error
