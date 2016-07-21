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

{-|

JSON Web Signature (JWS) represents content secured with digital
signatures or Message Authentication Codes (MACs) using JavaScript
Object Notation (JSON) based data structures.

-}
module Crypto.JOSE.JWS
  (
    Alg(..)

  , JWSHeader(..)
  , newJWSHeader
  , Protection(..)
  , HeaderParam(..)

  , JWS(..)
  , newJWS
  , jwsPayload
  , signJWS

  , HasValidationSettings(..)
  , HasAlgorithms(..)
  , HasValidationPolicy(..)

  , ValidationPolicy(..)
  , ValidationSettings
  , defaultValidationSettings
  , verifyJWS
  ) where

import Crypto.JOSE.JWA.JWS
import Crypto.JOSE.JWS.Internal
