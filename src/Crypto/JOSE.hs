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

{-|

Prelude for the  library.

-}
module Crypto.JOSE
  (
    vulnerableToHashFlood
  , module Crypto.JOSE.Compact
  , module Crypto.JOSE.Error
  , module Crypto.JOSE.JWK
  , module Crypto.JOSE.JWK.Store
  , module Crypto.JOSE.JWS
  ) where

import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import Crypto.JOSE.JWK
import Crypto.JOSE.JWK.Store
import Crypto.JOSE.JWS

import qualified Data.Aeson.KeyMap as KeyMap

{-# ANN module ("HLint: ignore Use import/export shortcut" :: String) #-}

-- | /aeson/ supports multiple map implementations.  The
-- implementation using @Data.HashMap@ from *unordered-containers*
-- is vulnerable to hash-flooding DoS attacks.  If your program
-- processes JOSE objects from untrusted sources, you can check this
-- value to find out if the *aeson* build uses a secure map
-- implementation, or not.
--
vulnerableToHashFlood :: Bool
vulnerableToHashFlood = case KeyMap.coercionToMap of
  -- Don't check that the map implementation is NOT Data.HashMap, in
  -- case some other insecure implementation emerges.  Instead,
  -- check that the implementation IS known to be secure.
  Just _  -> False
  Nothing -> True
