-- Copyright (C) 2016  Fraser Tweedale
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

{-# LANGUAGE ScopedTypeVariables #-}

{- |

Advanced Encryption Standard (AES) Key Wrap Algorithm;
<https://https://tools.ietf.org/html/rfc3394>.

-}
module Crypto.JOSE.AESKW
  (
    aesKeyWrap
  , aesKeyUnwrap
  ) where

import Control.Monad (join)
import Control.Monad.State (StateT, execStateT, get, lift, put)
import Crypto.Cipher.Types
import Data.Bits (xor)
import Data.ByteArray as BA hiding (replicate, xor)
import Data.Memory.Endian (BE(..), toBE)
import Data.Memory.PtrMethods (memCopy)
import Data.Word (Word64)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peek, peekElemOff, poke, pokeElemOff)
import System.IO.Unsafe (unsafePerformIO)

iv :: Word64
iv = 0xA6A6A6A6A6A6A6A6

aesKeyWrapStep
  :: BlockCipher128 cipher
  => cipher
  -> Ptr Word64   -- ^ register
  -> (Int, Int)   -- ^ step (t) and offset (i)
  -> StateT Word64 IO ()
aesKeyWrapStep cipher p (t, i) = do
  a <- get
  r_i <- lift $ peekElemOff p i
  m :: ScrubbedBytes <-
    lift $ alloc 16 $ \p' -> poke p' a >> pokeElemOff p' 1 r_i
  let b = ecbEncrypt cipher m
  b_hi <- lift $ withByteArray b peek
  b_lo <- lift $ withByteArray b (`peekElemOff` 1)
  put (b_hi `xor` unBE (toBE (fromIntegral t)))
  lift $ pokeElemOff p i b_lo

-- | Wrap a secret.
--
-- Input size must be a multiple of 8 bytes, and at least 16 bytes.
-- Output size is input size plus 8 bytes.
--
aesKeyWrap
  :: (ByteArrayAccess m, ByteArray c, BlockCipher128 cipher)
  => cipher
  -> m
  -> c
aesKeyWrap cipher m = unsafePerformIO $ do
  let n = BA.length m
  c <- withByteArray m $ \p ->
    alloc (n + 8) $ \p' ->
      memCopy (p' `plusPtr` 8) p n
  withByteArray c $ \p -> do
    let coords = zip [1..] (join (replicate 6 [1 .. n `div` 8]))
    a <- execStateT (mapM_ (aesKeyWrapStep cipher p) coords) iv
    poke p a
  return c

aesKeyUnwrapStep
  :: BlockCipher128 cipher
  => cipher
  -> Ptr Word64   -- ^ register
  -> (Int, Int)   -- ^ step (t) and offset (i)
  -> StateT Word64 IO ()
aesKeyUnwrapStep cipher p (t, i) = do
  a <- get
  r_i <- lift $ peekElemOff p i
  let a_t = a `xor` unBE (toBE (fromIntegral t))
  m :: ScrubbedBytes <-
    lift $ alloc 16 $ \p' -> poke p' a_t >> pokeElemOff p' 1 r_i
  let b = ecbDecrypt cipher m
  b_hi <- lift $ withByteArray b peek
  b_lo <- lift $ withByteArray b (`peekElemOff` 1)
  put b_hi
  lift $ pokeElemOff p i b_lo

-- | Unwrap a secret.
--
-- Input size must be a multiple of 8 bytes, and at least 24 bytes.
-- Output size is input size minus 8 bytes.
--
-- Returns 'Nothing' if inherent integrity check fails.  Otherwise,
-- the chance that the key data is corrupt is 2 ^ -64.
--
aesKeyUnwrap
  :: (ByteArrayAccess c, ByteArray m, BlockCipher128 cipher)
  => cipher
  -> c
  -> Maybe m
aesKeyUnwrap cipher c = unsafePerformIO $ do
  let n = BA.length c - 8
  m <- withByteArray c $ \p' ->
    alloc n $ \p ->
      memCopy p (p' `plusPtr` 8) n
  a <- withByteArray c $ \p' -> peek p'
  a' <- withByteArray m $ \p -> do
    let n' = n `div` 8
    let tMax = n' * 6
    let coords = zip [tMax,tMax-1..1] (cycle [n'-1,n'-2..0])
    execStateT (mapM_ (aesKeyUnwrapStep cipher p) coords) a
  return $ if a' == iv then Just m else Nothing
