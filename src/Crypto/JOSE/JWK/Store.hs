-- Copyright (C) 2013-2018  Fraser Tweedale
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

{-|

Key stores.  Instances are provided for 'JWK' and 'JWKSet'.  These
instances ignore the header and payload and just return the JWK/s
they contain.  More complex scenarios, such as efficient key lookup
by @"kid"@ or searching a database, can be implemented by writing a
new instance.

For example, the following instance looks in a filesystem directory
for keys based on either the JWS Header's @"kid"@ parameter, or the
  @"iss"@ claim in a JWT Claims Set:

@
-- | A KeyDB is just a filesystem directory
newtype KeyDB = KeyDB FilePath

instance (MonadIO m, HasKid h)
    => VerificationKeyStore m (h p) ClaimsSet KeyDB where
  getVerificationKeys h claims (KeyDB dir) = liftIO $
    fmap catMaybes . traverse findKey $ catMaybes
      [ preview (kid . _Just . param) h
      , preview (claimIss . _Just . string) claims]
    where
    findKey :: String -> IO (Maybe JWK)
    findKey s =
      let path = dir <> "/" <> s <> ".jwk"
      in handle
        (\(_ :: IOException) -> pure Nothing)
        (decode <$> L.readFile path)
@

-}
module Crypto.JOSE.JWK.Store
  (
    VerificationKeyStore(..)
  ) where

import Crypto.JOSE.JWK (JWK, JWKSet(..))

-- | Verification keys.  Lookup operates in effect @m@ with access
-- to the JWS header of type @h@ and a payload of type @s@.
--
-- The returned keys are not guaranteed to be used, e.g. if the JWK
-- @"use"@ or @"key_ops"@ field does not allow use for verification.
--
class VerificationKeyStore m h s a where
  -- | Look up verification keys by JWS header and payload.
  getVerificationKeys
    :: h          -- ^ JWS header
    -> s          -- ^ Payload
    -> a
    -> m [JWK]

-- | Use a 'JWK' as a 'VerificationKeyStore'.  Can be used with any
-- payload type.  Header and payload are ignored.  No filtering is
-- performed.
--
instance Applicative m => VerificationKeyStore m h s JWK where
  getVerificationKeys _ _ k = pure [k]

-- | Use a 'JWKSet' as a 'VerificationKeyStore'.  Can be used with
-- any payload type.  Returns all keys in the set; header and
-- payload are ignored.  No filtering is performed.
--
instance Applicative m => VerificationKeyStore m h s JWKSet where
  getVerificationKeys _ _ (JWKSet xs) = pure xs
