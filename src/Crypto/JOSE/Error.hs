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

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-|

JOSE error types.

-}
module Crypto.JOSE.Error
  (
    Error(..)
  , AsError(..)
  ) where

import Control.Monad.Trans (MonadTrans(..))
import qualified Crypto.PubKey.RSA as RSA
import Crypto.Error (CryptoError)
import Crypto.Random (MonadRandom(..))
import Control.Lens.TH (makeClassyPrisms)

-- | All the errors that can occur.
--
data Error
  = AlgorithmNotImplemented   -- ^ A requested algorithm is not implemented
  | AlgorithmMismatch String  -- ^ A requested algorithm cannot be used
  | KeyMismatch String        -- ^ Wrong type of key was given
  | KeySizeTooSmall           -- ^ Key size is too small
  | KeySizeInvalid            -- ^ Key size is invalid for algorithm
  | OtherPrimesNotSupported   -- ^ RSA private key with >2 primes not supported
  | RSAError RSA.Error        -- ^ RSA encryption, decryption or signing error
  | CryptoError CryptoError   -- ^ Various cryptonite library error cases
  | CompactDecodeError String -- ^ Cannot decode compact representation
  | JSONDecodeError String    -- ^ JSON (Aeson) decoding error
  | JWSCritUnprotected
  | JWSNoValidSignatures
  -- ^ 'AnyValidated' policy active, and no valid signature encountered
  | JWSInvalidSignature
  -- ^ 'AllValidated' policy active, and invalid signature encountered
  | JWSNoSignatures
  -- ^ 'AllValidated' policy active, and there were no signatures on object
  --   that matched the allowed algorithms
  | InvalidTag
  -- ^ The authenticated tag of an authenticated encryption is not valid
  deriving (Eq, Show)
makeClassyPrisms ''Error


instance (
    MonadRandom m
  , MonadTrans t
  , Functor (t m)
  , Monad (t m)
  ) => MonadRandom (t m) where
    getRandomBytes = lift . getRandomBytes
