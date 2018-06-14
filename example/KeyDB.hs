{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}

module KeyDB
  (
    KeyDB(..)
  ) where

import Control.Exception (IOException, handle)
import Data.Semigroup ((<>))

import Control.Monad.Trans (MonadIO(..))
import Control.Lens (_Just, preview)
import Data.Aeson (decode)
import qualified Data.ByteString.Lazy as L

import Crypto.JWT

-- | Looks for keys given a FilePath.  'keys' returns empty
-- list but 'keysFor' will try to find a key based on the
-- "iss" field of the JWT.
--
newtype KeyDB = KeyDB FilePath

instance MonadIO m => VerificationKeyStore m ClaimsSet KeyDB where
  getVerificationKeys _ claims (KeyDB dir) = liftIO $
    case preview (claimIss . _Just . string) claims of
      Nothing -> pure []
      Just iss ->
        let path = dir <> "/" <> iss <> ".jwk"
        in handle
          (\(_ :: IOException) -> pure [])
          (maybe [] pure . decode <$> L.readFile path)
