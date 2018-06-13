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

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-|

A 'JWKStore' provides JWK enumeration and lookup.

-}
module Crypto.JOSE.JWK.Store
  (
    JWKStore(..)
  ) where

import Data.Proxy

import Crypto.JOSE.Header
import Crypto.JOSE.JWK (JWK, JWKSet(..), KeyOp)

class JWKStore m s a where
  -- | Retrieve all keys in the store
  keys :: Proxy s -> a -> m [JWK]

  -- | Look up key by JWS/JWE header and payload
  keysFor
    ::  ( HasAlg h, HasJku h, HasJwk h, HasKid h
        , HasX5u h, HasX5c h, HasX5t h, HasX5tS256 h
        , HasTyp h, HasCty h )
    => KeyOp
    -> h p        -- ^ JWS header
    -> s          -- ^ Payload
    -> a
    -> m [JWK]
  keysFor _ _ _ = keys (Proxy :: Proxy s)


-- | Use a 'JWK' as a 'JWKStore'.  No filtering is performed.
--
instance Applicative m => JWKStore m s JWK where
  keys _ k = pure [k]

-- | Use a 'JWKSet' as a 'JWKStore'.  No filtering is performed.
--
instance Applicative m => JWKStore m s JWKSet where
  keys _ (JWKSet xs) = pure xs
