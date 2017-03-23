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

@
doJwsSign :: 'JWK' -> L.ByteString -> IO (Either 'Error' ('JWS' 'JWSHeader'))
doJwsSign jwk payload = runExceptT $ do
  alg \<- 'bestJWSAlg' jwk
  'signJWS' ('newJWS' payload) ('newJWSHeader' ('Protected', alg)) jwk

doJwsVerify :: 'JWK' -> 'JWS' 'JWSHeader' -> IO (Either 'Error' ())
doJwsVerify jwk jws = runExceptT $ 'verifyJWS'' jwk jws
@

-}
module Crypto.JOSE.JWS
  (
  -- * JWS creation
    newJWS
  , newJWSHeader
  , signJWS

  -- * JWS verification
  , verifyJWS
  , verifyJWS'

  -- * JWS validation settings
  , defaultValidationSettings
  , ValidationSettings
  , ValidationPolicy(..)
  , HasValidationSettings(..)
  , HasAlgorithms(..)
  , HasValidationPolicy(..)

  -- * JWS objects
  , JWS
  , payload
  , signatures
  , Signature
  , header
  , signature

  -- * JWS headers
  , Alg(..)
  , HasJWSHeader(..)
  , JWSHeader

  , module Crypto.JOSE.Error
  , module Crypto.JOSE.Header
  , module Crypto.JOSE.JWK
  ) where

import Crypto.JOSE.Error
import Crypto.JOSE.JWA.JWS
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS.Internal
import Crypto.JOSE.Header
