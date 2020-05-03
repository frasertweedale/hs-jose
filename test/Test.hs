-- Copyright (C) 2013, 2014, 2015  Fraser Tweedale
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

import Test.Tasty
import Test.Tasty.Hspec
import Test.Tasty.QuickCheck

import AESKW
import Examples
import JWK
import JWS
import JWT
import Types
import Properties


main :: IO ()
main = do
  unitTests <- unitTestsIO
  defaultMain $ testGroup "Tests" [unitTests, properties, aeskwProperties]

unitTestsIO :: IO TestTree
unitTestsIO = do
  types <- testSpec "Types" Types.spec
  jwk <- testSpec "JWK" JWK.spec
  jws <- testSpec "JWS" JWS.spec
  jwt <- testSpec "JWT" JWT.spec
  examples <- testSpec "Examples" Examples.spec
  return $ testGroup "Unit tests" [types, jwk, jws, jwt, examples]
