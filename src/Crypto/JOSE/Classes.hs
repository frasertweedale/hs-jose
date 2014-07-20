-- Copyright (C) 2013, 2014  Fraser Tweedale
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

{-# LANGUAGE TypeFamilies #-}

{-|

Type classes for use with the JOSE modules.

-}
module Crypto.JOSE.Classes
  (
    module Crypto.Random
  , Key(..)
  ) where

import qualified Data.ByteString as B

import Crypto.Random

import qualified Crypto.JOSE.JWA.JWS as JWA.JWS
import Crypto.JOSE.Error

-- | A Key that can sign messages and validate signatures according
-- to a given 'Alg'.
--
-- Can fail with 'AlgorithmMismatch'
--
class Key k where
  type KeyGenParam k
  gen :: CPRG g => KeyGenParam k -> g -> (k, g)
  sign
    :: CPRG g
    => JWA.JWS.Alg
    -> k
    -> g
    -> B.ByteString
    -> (Either Error B.ByteString, g)
  verify
    :: JWA.JWS.Alg
    -> k
    -> B.ByteString
    -> B.ByteString
    -> Either Error Bool
