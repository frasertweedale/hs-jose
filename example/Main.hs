import Data.Maybe (fromJust)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)

import Control.Lens ((^.))
import qualified Data.ByteString.Lazy as L
import Data.Aeson (decode, encode)

import Control.Monad.Except (runExceptT)
import Crypto.JOSE.JWK
  ( KeyMaterialGenParam(..), jwkMaterial, KeyMaterial(..)
  , Crv(..), genJWK, bestJWSAlg
  )
import Crypto.JWT (
  createJWSJWT,
  validateJWSJWT, defaultJWTValidationSettings, JWTError)
import Crypto.JOSE.Compact (decodeCompact, encodeCompact)
import Crypto.JOSE.JWS (Alg(..), Protection(Protected), newJWSHeader)

import Crypto.JOSE.Error (Error)

main :: IO ()
main = do
  args <- getArgs
  case head args of
    "jwk-gen" -> doGen (tail args)
    "jwt-sign" -> doJwtSign (tail args)
    "jwt-verify" -> doJwtVerify (tail args)

doGen :: [String] -> IO ()
doGen [kty] = do
  let
    param = case kty of
      "oct" -> OctGenParam 32
      "rsa" -> RSAGenParam 256
      "ec" -> ECGenParam P_256
  jwk <- genJWK param
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
  let
    jwk = fromJust (decode jwkData)
    claims = fromJust (decode claimsData)
    alg = case jwk ^. jwkMaterial of
      OctKeyMaterial _ -> HS256
      RSAKeyMaterial _ -> RS256
      ECKeyMaterial _ -> ES256
  let header = newJWSHeader (Protected, alg)
  result <- runExceptT $ do
    alg <- bestJWSAlg jwk
    createJWSJWT jwk header claims >>= encodeCompact
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
