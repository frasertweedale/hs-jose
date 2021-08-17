-- Copyright (C) 2014, 2015, 2016  Fraser Tweedale
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

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Crypto.JOSE.Types.Orphans where

import Data.Aeson
import qualified Data.Text as T
import Network.URI (URI, parseURI)


instance FromJSON URI where
  parseJSON = withText "URI" $
    maybe (fail "not a URI") return . parseURI . T.unpack

instance ToJSON URI where
  toJSON = String . T.pack . show
