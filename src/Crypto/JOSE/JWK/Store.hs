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

A 'JWKStore' provides JWK enumeration and lookup, possibly with
effects.

The 'keysFor' function is used to perform key lookup.  It can read
JWS header and the JWS payload to help choose or find the relevant
keys.

Instances are provided for 'JWK' and 'JWKSet'.  These instances
ignore the header and payload and just return the JWK/s they
contain.

More complex scenarios, such as efficient key lookup by @"kid"@ or
searching a database, can be implemented by writing a new instance.
For example, the following instance looks in a filesystem directory
for keys based on the @"iss"@ claim in a JWT Claims Set:

@
-- | A KeyDB is just a filesystem directory
newtype KeyDB = KeyDB FilePath

instance MonadIO m => JWKStore m ClaimsSet KeyDB where
  keys _ _ = pure []
  keysFor _ _ claims (KeyDB dir) = liftIO $
    case preview (claimIss . _Just . string) claims of
      Nothing -> pure []
      Just iss ->
        -- Look for a file name "${iss}.jwk"
        let path = dir <> "/" <> iss <> ".jwk"
        in handle
          -- IO errors (file not found, not readable, etc) return []
          (\(_ :: IOException) -> pure [])
          (maybe [] pure . decode \<$\> L.readFile path)
@

-}
module Crypto.JOSE.JWK.Store
  (
    JWKStore(..)
  ) where

import Data.Proxy

import Crypto.JOSE.Header
import Crypto.JOSE.JWK (JWK, JWKSet(..), KeyOp)

-- | A key database.  Lookup operates in effect @m@, with access
-- to payload type 's'.
--
class JWKStore m s a where
  -- | Retrieve all keys in the store.
  keys :: Proxy s -> a -> m [JWK]

  -- | Look up key by JWS/JWE header and payload.
  -- The default implementation returns all 'keys'.
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

  {-# MINIMAL keys #-}

-- | Use a 'JWK' as a 'JWKStore'.  No filtering is performed.
--
instance Applicative m => JWKStore m s JWK where
  keys _ k = pure [k]

-- | Use a 'JWKSet' as a 'JWKStore'.  No filtering is performed.
--
instance Applicative m => JWKStore m s JWKSet where
  keys _ (JWKSet xs) = pure xs
