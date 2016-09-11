import Data.Maybe (fromJust)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)

import qualified Data.ByteString.Lazy as L
import Data.Aeson (decode, encode)

import Control.Monad.Except (runExceptT)
import Crypto.JOSE.JWK (KeyMaterialGenParam(OctGenParam), genJWK)
import Crypto.JWT (
  createJWSJWT,
  validateJWSJWT, defaultJWTValidationSettings, JWTError)
import Crypto.JOSE.Compact (decodeCompact, encodeCompact)
import Crypto.JOSE.JWS (Alg(HS256), Protection(Protected), newJWSHeader)

import Crypto.JOSE.Error (Error)

main :: IO ()
main = do
  args <- getArgs
  case head args of
    "jwk-gen" -> doGen
    "jwt-sign" -> doJwtSign (tail args)
    "jwt-verify" -> doJwtVerify (tail args)

doGen :: IO ()
doGen = do
  jwk <- genJWK (OctGenParam 32)
  L.putStr (encode jwk)

-- | Mint a JWT.  Args are:
--
-- 1. filename of JWK
-- 2. filename of a claims object
--
-- Output is a signed JWT.
--
doJwtSign :: [String] -> IO ()
doJwtSign [jwkFilename, claimsFilename] = do
  jwkData <- L.readFile jwkFilename
  claimsData <- L.readFile claimsFilename
  let jwk = fromJust (decode jwkData)
  let claims = fromJust (decode claimsData)
  let header = newJWSHeader (Protected, HS256)
  result <- runExceptT (createJWSJWT jwk header claims >>= encodeCompact)
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right jwtData -> L.putStr jwtData


-- | Validate a JWT.  Args are:
--
-- 1. filename of JWK
-- 2. filename of a claims object
--
-- Exit code indicates validity.
--
doJwtVerify :: [String] -> IO ()
doJwtVerify [jwkFilename, jwtFilename] = do
  jwkData <- L.readFile jwkFilename
  jwtData <- L.readFile jwtFilename
  let jwk = fromJust (decode jwkData)
  result <- runExceptT (
    decodeCompact jwtData
    >>= validateJWSJWT defaultJWTValidationSettings jwk)
  case result of
    Left e -> print (e :: JWTError) >> exitFailure
    Right _ -> exitSuccess
