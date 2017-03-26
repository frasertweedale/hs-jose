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
Object Notation (JSON) based data structures.  It is defined in
<https://tools.ietf.org/html/rfc7515 RFC 7515>.

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
  -- ** Defining additional header parameters
  -- $extending

  -- * JWS creation
    newJWS
  , newJWSHeader
  , signJWS

  -- * JWS verification
  , verifyJWS
  , verifyJWS'

  -- ** JWS validation settings
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


{- $extending

Several specifications extend JWS with additional header parameters.
The 'JWS' type is parameterised over the header type; this library
provides the 'JWSHeader' type which encompasses all the JWS header
parameters defined in RFC 7515.  To define an extended header type
declare the data type, and instances for 'HasJWSHeader' and
'HasParams'.  For example:

@
data ACMEHeader = ACMEHeader
  { _acmeJwsHeader :: 'JWSHeader'
  , _acmeNonce :: 'Types.Base64Octets'
  }

acmeJwsHeader :: Lens' ACMEHeader JWSHeader
acmeJwsHeader f s@(ACMEHeader { _acmeJwsHeader = a}) =
  fmap (\a' -> s { _acmeJwsHeader = a'}) (f a)

acmeNonce :: Lens' ACMEHeader Types.Base64Octets
acmeNonce f s@(ACMEHeader { _acmeNonce = a}) =
  fmap (\a' -> s { _acmeNonce = a'}) (f a)

instance HasJWSHeader ACMEHeader where
  jWSHeader = acmeJwsHeader

instance HasParams ACMEHeader where
  'parseParamsFor' proxy hp hu = ACMEHeader
    \<$> 'parseParamsFor' proxy hp hu
    \<*> 'headerRequiredProtected' "nonce" hp hu
  params h =
    (Protected, "nonce" .= view acmeNonce h)
    : 'params' (view acmeJwsHeader h)
  'extensions' = const ["nonce"]
@

See also:

- 'HasParams'
- 'headerRequired'
- 'headerRequiredProtected'
- 'headerOptional'
- 'headerOptionalProtected'

-}
