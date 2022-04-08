-- Copyright (C) 2014-2022  Fraser Tweedale
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

  , JOSE
  , runJOSE
  , unwrapJOSE
  ) where

import Data.Semigroup ((<>))
import Numeric.Natural

import Control.Monad.Except
import qualified Crypto.PubKey.RSA as RSA
import Crypto.Error (CryptoError)
import Crypto.Random (MonadRandom(..))
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


newtype JOSE e m a = JOSE (ExceptT e m a)

-- | Run the 'JOSE' computation.  Result is an @Either e a@
-- where @e@ is the error type (typically 'Error' or 'JWTError')
runJOSE :: JOSE e m a -> m (Either e a)
runJOSE = runExceptT . (\(JOSE m) -> m)

-- | Get the inner 'ExceptT' value of the 'JOSE' computation.
-- Typically 'runJOSE' would be preferred, unless you specifically
-- need an 'ExceptT' value.
unwrapJOSE :: JOSE e m a -> ExceptT e m a
unwrapJOSE (JOSE m) = m


instance (Functor m) => Functor (JOSE e m) where
  fmap f (JOSE ma) = JOSE (fmap f ma)

instance (Monad m) => Applicative (JOSE e m) where
  pure = JOSE . pure
  JOSE mf <*> JOSE ma = JOSE (mf <*> ma)

instance (Monad m) => Monad (JOSE e m) where
  JOSE ma >>= f = JOSE (ma >>= unwrapJOSE . f)

instance MonadTrans (JOSE e) where
  lift = JOSE . lift

instance (Monad m) => MonadError e (JOSE e m) where
  throwError = JOSE . throwError
  catchError (JOSE m) handle = JOSE (catchError m (unwrapJOSE . handle))

instance (MonadIO m) => MonadIO (JOSE e m) where
  liftIO = JOSE . liftIO

instance (MonadRandom m) => MonadRandom (JOSE e m) where
    getRandomBytes = lift . getRandomBytes
