-- Copyright (C) 2017-2022  Fraser Tweedale
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

{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module JWS
  ( doJwsSign
  , doJwsVerify
  ) where

import System.Exit (exitFailure)

import Data.Aeson (decode, encode)
import qualified Data.ByteString.Lazy as L

import Crypto.JOSE.JWS

-- | Create a JWS.  Args are:
--
-- 1. filename of JWK
-- 2. filename of payload
--
-- Output is a signed JWS (JSON serialisation).
--
doJwsSign :: [String] -> IO ()
doJwsSign [jwkFilename, payloadFilename] = do
  Just k <- decode <$> L.readFile jwkFilename
  payload <- L.readFile payloadFilename
  result <- runJOSE $ do
    h <- makeJWSHeader k
    signJWS payload [(h :: JWSHeader OptionalProtection, k)]
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right jws -> L.putStr (encode jws)


-- | Verify a JWS and output the payload if valid.  Args are:
--
-- 1. filename of JWK
-- 2. filename of JWS
--
-- Exit code indicates validity.
--
doJwsVerify :: [String] -> IO ()
doJwsVerify [jwkFilename, jwsFilename] = do
  Just k <- decode <$> L.readFile jwkFilename
  Just jws <- decode <$> L.readFile jwsFilename
  result <- runJOSE $ verifyJWS' (k :: JWK) (jws :: GeneralJWS JWSHeader)
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right s -> L.putStr s
