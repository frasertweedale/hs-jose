-- | Miscellaneous end-to-end examples.
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
module Examples where

import Control.Lens (_Right, (&), (?~), (.~))
import Control.Lens.Extras (is)
import qualified Data.ByteString.Char8 as BC8
import qualified Data.PEM as PEM
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import qualified Data.X509 as X509

import Crypto.JOSE.JWK
import Crypto.JWT

import Test.Hspec

spec :: Spec
spec = do
  fromX509VerifySpec

fromX509VerifySpec :: Spec
fromX509VerifySpec =
  describe "Decode PEM-encoded X509 EC certificate and verify" $ do
    let certs = do
          pems <- PEM.pemParseBS pemEncodedX509
          mapM (X509.decodeSignedCertificate . PEM.pemContent) pems

    it "successfully parses the single X509 certificate" $ do
      certs `shouldSatisfy` \case Right [_] -> True; _ -> False

    case certs of
      Right [x509] -> do
        let errorOrJWK = fromX509Certificate x509 :: Either JWTError JWK
        it "successfully converts the X509 certificate to a JWK" $
          errorOrJWK `shouldSatisfy` is _Right

        it "verifies a token signed using ES256 and matches expected claims" $
          (do
            es256jwk <- errorOrJWK
            jwt <- decodeCompact es256token
            verifyClaimsAt valSettings es256jwk now jwt) `shouldBe`
          Right expectedClaims

      _ -> pure ()
  where

  es256token = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.eyJuYmYiOiAxNDQ0NDc4NDAwLCAiaXNzIjogInh4eCJ9.lArczfN-pIL8oUU-7PU83u-zfXougXBZj6drFeKFsPEoVhy9WAyiZlRshYqjTSXdaw8yw2L-ovt4zTUZb2PWMg"

  pemEncodedX509 = BC8.unlines
    [ "-----BEGIN CERTIFICATE-----"
    , "MIIBcDCCARagAwIBAgIJAMZmuGSIfvgzMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM"
    , "CHdoYXRldmVyMB4XDTE4MDgxMDE0Mjg1NFoXDTE4MDkwOTE0Mjg1NFowEzERMA8G"
    , "A1UEAwwId2hhdGV2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATPwn3WCEXL"
    , "mjp/bFniDwuwsfu7bASlPae2PyWhqGeWwe23Xlyx+tSqxlkXYe4pZ23BkAAscpGj"
    , "yn5gXHExyDlKo1MwUTAdBgNVHQ4EFgQUElRjSoVgKjUqY5AXz2o74cLzzS8wHwYD"
    , "VR0jBBgwFoAUElRjSoVgKjUqY5AXz2o74cLzzS8wDwYDVR0TAQH/BAUwAwEB/zAK"
    , "BggqhkjOPQQDAgNIADBFAiEA4yQ/88ZrUX68c6kOe9G11u8NUaUzd8pLOtkKhniN"
    , "OHoCIHmNX37JOqTcTzGn2u9+c8NlnvZ0uDvsd1BmKPaUmjmm"
    , "-----END CERTIFICATE-----"
    ]

  now = posixSecondsToUTCTime 1588512349

  expectedClaims = emptyClaimsSet
    & claimIss ?~ "xxx"
    & claimNbf ?~ NumericDate (posixSecondsToUTCTime 1444478400)

  valSettings = defaultJWTValidationSettings (const True)
    & jwtValidationSettingsIssuerPredicate .~ (== "xxx")
