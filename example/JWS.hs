module JWS where

import System.Exit (exitFailure)

import Control.Monad.Except (runExceptT)
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
  Just jwk <- decode <$> L.readFile jwkFilename
  payload <- L.readFile payloadFilename
  result <- runExceptT $ do
    h <- makeJWSHeader jwk
    signJWS payload [(h :: JWSHeader Protection, jwk)]
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
  Just jwk <- decode <$> L.readFile jwkFilename
  Just jws <- decode <$> L.readFile jwsFilename
  result <- runExceptT $ verifyJWS' (jwk :: JWK) (jws :: GeneralJWS JWSHeader)
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right s -> L.putStr s
