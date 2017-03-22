{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}
{-# LANGUAGE CPP #-}

import Data.Maybe (fromJust)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Aeson (decode, encode)

import Control.Monad.Except (runExceptT)
import Control.Lens (preview, review, set)
import Crypto.JOSE.JWK
  ( KeyMaterialGenParam(..), Crv(..), JWK, genJWK, bestJWSAlg
#if MIN_VERSION_aeson(0,10,0)
  , Digest, SHA256, thumbprint, convert
#endif
  )
import Crypto.JOSE.Types (base64url)
import Crypto.JWT
  ( JWTError
  , createJWSJWT
  , validateJWSJWT
  , defaultJWTValidationSettings
  , audiencePredicate
  , stringOrUri
  )
import Crypto.JOSE.Compact (decodeCompact, encodeCompact)
import Crypto.JOSE.JWS (Protection(Protected), newJWSHeader)

import Crypto.JOSE.Error (Error)

main :: IO ()
main = do
  args <- getArgs
  case head args of
    "jwk-gen" -> doGen (tail args)
    "jwt-sign" -> doJwtSign (tail args)
    "jwt-verify" -> doJwtVerify (tail args)
#if MIN_VERSION_aeson(0,10,0)
    "jwk-thumbprint" -> doThumbprint (tail args)
#endif

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
  Just jwk <- decode <$> L.readFile jwkFilename
  Just claims <- decode <$> L.readFile claimsFilename
  result <- runExceptT $ do
    alg <- bestJWSAlg jwk
    let header = newJWSHeader (Protected, alg)
    createJWSJWT jwk header claims >>= encodeCompact
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right jwtData -> L.putStr jwtData


-- | Validate a JWT.  Args are:
--
-- 1. filename of JWK
-- 2. filename of a JWT
-- 3. audience
--
-- Extraneous trailing args are ignored.
--
-- Exit code indicates validity.
--
doJwtVerify :: [String] -> IO ()
doJwtVerify (jwkFilename : jwtFilename : aud : _) = do
  let
    aud' = fromJust $ preview stringOrUri aud
    conf = set audiencePredicate (== aud') defaultJWTValidationSettings
  Just jwk <- decode <$> L.readFile jwkFilename
  jwtData <- L.readFile jwtFilename
  result <- runExceptT
    (decodeCompact jwtData >>= validateJWSJWT conf (jwk :: JWK))
  case result of
    Left e -> print (e :: JWTError) >> exitFailure
    Right _ -> exitSuccess


#if MIN_VERSION_aeson(0,10,0)
-- | Print a base64url-encoded SHA-256 JWK Thumbprint.  Args are:
--
-- 1. filename of JWK
--
doThumbprint :: [String] -> IO ()
doThumbprint (jwkFilename : _) = do
  Just jwk <- decode <$> L.readFile jwkFilename
  let
    h = thumbprint jwk :: Digest SHA256
    bs = convert h :: B.ByteString
    s = review base64url bs :: B.ByteString
  print s
#endif
