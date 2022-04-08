-- Copyright (C) 2014-2022  Fraser Tweedale
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

module Crypto.JOSE.Types.URI
  ( uriFromJSON
  , uriToJSON
  ) where

import Data.Aeson
import Data.Aeson.Types (Parser)
import qualified Data.Text as T
import Network.URI (URI, parseURI)

uriFromJSON :: Value -> Parser URI
uriFromJSON = withText "URI" $ maybe (fail "not a URI") pure . parseURI . T.unpack

uriToJSON :: URI -> Value
uriToJSON = String . T.pack . show
