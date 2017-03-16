-- Copyright (C) 2013  Fraser Tweedale
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

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

{-|

JSON Web Signature algorithms.

-}
module Crypto.JOSE.JWA.JWS where

import qualified Crypto.JOSE.TH


-- | RFC 7518 §3.1.  "alg" (Algorithm) Header Parameters Values for JWS
--
$(Crypto.JOSE.TH.deriveJOSEType "Alg" [
  "HS256"   -- HMAC SHA ; REQUIRED
  , "HS384" -- HMAC SHA ; OPTIONAL
  , "HS512" -- HMAC SHA ; OPTIONAL
  , "RS256" -- RSASSA-PKCS-v1_5 SHA ; RECOMMENDED
  , "RS384" -- RSASSA-PKCS-v1_5 SHA ; OPTIONAL
  , "RS512" -- RSASSA-PKCS-v1_5 SHA ; OPTIONAL
  , "ES256" -- ECDSA P curve and SHA ; RECOMMENDED+
  , "ES384" -- ECDSA P curve and SHA ; OPTIONAL
  , "ES512" -- ECDSA P curve and SHA ; OPTIONAL
  , "PS256" -- RSASSA-PSS SHA ; OPTIONAL
  , "PS384" -- RSASSA-PSS SHA ; OPTIONAL
  , "PS512" -- RSSSSA-PSS SHA ; OPTIONAL
  , "none"  -- "none" No signature or MAC ; Optional
  , "EdDSA" -- EdDSA (RFC 8037)
  ])
