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

{-# LANGUAGE RankNTypes #-}

{-|

A 'JWKStore' provides JWK enumeration and lookup.

-}
module Crypto.JOSE.JWK.Store
  (
    JWKStore(..)
  ) where


import Control.Lens (Fold, folding)

import Crypto.JOSE.Header
import Crypto.JOSE.JWK (JWK, JWKSet(..), KeyOp)

class JWKStore a where
  -- | Enumerate keys
  keys :: Fold a JWK

  -- | Look up key by JWS/JWE header
  keysFor
    ::  ( HasAlg h, HasJku h, HasJwk h, HasKid h
        , HasX5u h, HasX5c h, HasX5t h, HasX5tS256 h
        , HasTyp h, HasCty h )
    => KeyOp
    -> h p
    -> Fold a JWK
  keysFor _ _ = keys


instance JWKStore JWK where
  keys = id

instance JWKStore JWKSet where
  keys = folding (\(JWKSet xs) -> xs)
