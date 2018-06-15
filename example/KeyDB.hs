{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}

module KeyDB
  (
    KeyDB(..)
  ) where

import Control.Exception (IOException, handle)
import Data.Maybe (catMaybes)
import Data.Semigroup ((<>))

import Control.Monad.Trans (MonadIO(..))
import Control.Lens (_Just, preview)
import Data.Aeson (decode)
import qualified Data.ByteString.Lazy as L

import Crypto.JWT

-- | A KeyDB is just a directory
--
newtype KeyDB = KeyDB FilePath

-- | Looks for a key in the directory, based on the @"kid"@ field of
-- the 'JWSHeader' or the @"iss"@ field of the JWT 'ClaimsSet'
--
instance (MonadIO m, HasKid h)
    => VerificationKeyStore m (h p) ClaimsSet KeyDB where
  getVerificationKeys h claims (KeyDB dir) = liftIO $
    fmap catMaybes . traverse findKey $ catMaybes
      [ preview (kid . _Just . param) h
      , preview (claimIss . _Just . string) claims]
    where
    findKey :: String -> IO (Maybe JWK)
    findKey s =
      let path = dir <> "/" <> s <> ".jwk"
      in handle
        (\(_ :: IOException) -> pure Nothing)
        (decode <$> L.readFile path)
