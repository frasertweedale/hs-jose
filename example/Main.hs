{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}
{-# LANGUAGE CPP #-}

import Data.Maybe (fromJust)
import System.Environment (getArgs)
import System.Exit (exitFailure)

import qualified Data.ByteString.Lazy as L
import Data.Aeson (decode, encode)
import Data.Text.Strict.Lens (utf8)

import Control.Monad.Except (runExceptT)
import Control.Lens (preview, re, review, set, view)
import Crypto.JOSE.JWK
  ( KeyMaterialGenParam(..) , Crv(P_256), OKPCrv(Ed25519)
  , JWK, genJWK, jwkKid, bestJWSAlg
#if MIN_VERSION_aeson(0,10,0)
  , Digest, SHA256, thumbprint, digest, base64url
#endif
  )
import Crypto.JWT
import Crypto.JOSE.Compact (decodeCompact, encodeCompact)
import Crypto.JOSE.JWS (Protection(Protected), newJWSHeader)

import Crypto.JOSE.Error (Error)

import JWS (doJwsSign, doJwsVerify)

main :: IO ()
main = do
  args <- getArgs
  case head args of
    "jwk-gen" -> doGen (tail args)
    "jws-sign" -> doJwsSign (tail args)
    "jws-verify" -> doJwsVerify (tail args)
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
      "eddsa" -> OKPGenParam Ed25519
  jwk <- genJWK param
#if MIN_VERSION_aeson(0,10,0)
  let
    h = view thumbprint jwk :: Digest SHA256
    kid = view (re (base64url . digest) . utf8) h
    jwk' = set jwkKid (Just kid) jwk
#else
  let jwk' = jwk
#endif
  L.putStr (encode jwk')

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
    signClaims jwk header claims >>= encodeCompact
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
-- If JWT is valid, output JSON claims and exit 0,
-- otherwise exit nonzero.
--
doJwtVerify :: [String] -> IO ()
doJwtVerify [jwkFilename, jwtFilename, aud] = do
  let
    aud' = fromJust $ preview stringOrUri aud
    conf = defaultJWTValidationSettings (== aud')
  Just jwk <- decode <$> L.readFile jwkFilename
  jwtData <- L.readFile jwtFilename
  result <- runExceptT
    (decodeCompact jwtData >>= verifyClaims conf (jwk :: JWK))
  case result of
    Left e -> print (e :: JWTError) >> exitFailure
    Right claims -> L.putStr $ encode claims


#if MIN_VERSION_aeson(0,10,0)
-- | Print a base64url-encoded SHA-256 JWK Thumbprint.  Args are:
--
-- 1. filename of JWK
--
doThumbprint :: [String] -> IO ()
doThumbprint (jwkFilename : _) = do
  Just jwk <- decode <$> L.readFile jwkFilename
  let h = view thumbprint jwk :: Digest SHA256
  L.putStr $ review (base64url . digest) h
#endif
