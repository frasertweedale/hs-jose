{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE TupleSections #-}

import Data.Maybe (fromJust)
import System.Environment (getArgs)
import System.Exit (exitFailure)

import qualified Data.ByteString.Lazy as L
import Data.Aeson (decode, eitherDecode, encode)
import Data.Text.Strict.Lens (utf8)

import Control.Monad.Except (runExceptT)
import Control.Lens (preview, re, review, set, view)

import Crypto.JWT
import Crypto.JOSE.JWE

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
    "jwe-encrypt" -> doJweEncrypt (tail args)
    "jwe-decrypt" -> doJweDecrypt (tail args)
#if MIN_VERSION_aeson(0,10,0)
    "jwk-thumbprint" -> doThumbprint (tail args)
#endif

doGen :: [String] -> IO ()
doGen [kty] = do
  k <- genJWK $ case kty of
                  "oct" -> OctGenParam 32
                  "rsa" -> RSAGenParam 256
                  "ec" -> ECGenParam P_256
                  "eddsa" -> OKPGenParam Ed25519
#if MIN_VERSION_aeson(0,10,0)
  let
    h = view thumbprint k :: Digest SHA256
    kid' = view (re (base64url . digest) . utf8) h
    k' = set jwkKid (Just kid') k
#else
  let k' = k
#endif
  L.putStr (encode k')


doJweEncrypt :: [String] -> IO ()
doJweEncrypt (payloadFilename : recipients) = do
  ks <- fmap (either error id . eitherDecode) <$> traverse L.readFile recipients
  payload <- L.readFile payloadFilename
  result <- runExceptT $
    traverse bestJWEAlg ks >>=
      encryptJWE bestJWEEnc payload (mempty :: L.ByteString)
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right jwe -> L.putStr (encode (jwe :: GeneralJWE))

doJweDecrypt :: [String] -> IO ()
doJweDecrypt [jwkFilename, jweFilename] = do
  k <- either error id . eitherDecode <$> L.readFile jwkFilename
  jwe <- either error id . eitherDecode <$> L.readFile jweFilename
  result <- runExceptT $
    decryptJWE k (jwe :: GeneralJWE)
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right s -> L.putStr s


-- | Mint a JWT.  Args are:
--
-- 1. filename of JWK
-- 2. filename of a claims object
--
-- Output is a signed JWT.
--
doJwtSign :: [String] -> IO ()
doJwtSign [jwkFilename, claimsFilename] = do
  Just k <- decode <$> L.readFile jwkFilename
  Just claims <- decode <$> L.readFile claimsFilename
  result <- runExceptT $ do
    alg' <- bestJWSAlg k
    signClaims k (newJWSHeader ((), alg')) claims
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right jwt -> L.putStr (encodeCompact jwt)


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
  Just k <- decode <$> L.readFile jwkFilename
  jwtData <- L.readFile jwtFilename
  result <- runExceptT
    (decodeCompact jwtData >>= verifyClaims conf (k :: JWK))
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
  Just k <- decode <$> L.readFile jwkFilename
  let h = view thumbprint k :: Digest SHA256
  L.putStr $ review (base64url . digest) h
#endif
