{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}

{-

Test program for ensuring that verification of a large JWT
happens in reasonable time.  This program is based on a test
program published by Silvan Mosberger at:

  https://github.com/tweag/haskell-fido2/tree/a25308a07551ccd86af47774a74dbdf989454d51

Related: https://github.com/frasertweedale/hs-jose/pull/103

-}

import Control.Lens ((^?), _Just)
import Control.Monad.Except (ExceptT, runExceptT)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JWT (CompactJWS, HasX5c (x5c), JWSHeader, JWTError, RequiredProtection, decodeCompact, fromX509Certificate, param, verifyJWS')
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.List.NonEmpty (NonEmpty ((:|)))
import System.Timeout (timeout)
import System.Exit (die)

data Store = Store

instance VerificationKeyStore (ExceptT JWTError IO) (JWSHeader RequiredProtection) B.ByteString Store where
  getVerificationKeys header _ _ = do
    let Just (x :| _) = header ^? x5c . _Just . param
    res <- fromX509Certificate x
    return [res]

main :: IO ()
main = do
  s <- L.readFile path
  r <- timeout 500000 (go s)
  case r of
    Nothing -> die "Verifying the big JWT timed out!"
    Just _ -> pure ()
  where
    path = "test/data/fido.jwt"
    go :: L.ByteString -> IO ()
    go s = do
      r <- runExceptT $ do
        jws <- decodeCompact s
        verifyJWS' Store (jws :: CompactJWS JWSHeader)
      case r of
        Left err ->
          die $ "Verification failure: " ++ show (err :: JWTError)
        Right payload ->
          putStrLn $ "Payload verified (size = " ++ show (B.length payload) ++ ")"
