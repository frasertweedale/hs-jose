{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}

module KeyDB
  (
    KeyDB(..)
  ) where

import Control.Exception (SomeException, handle)
import Data.Maybe (fromJust)
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

instance MonadIO m => JWKStore m ClaimsSet KeyDB where
  keys _ _ = pure []
  keysFor _ _ claims (KeyDB dir) = liftIO $
    case preview (claimIss . _Just . string) claims of
      Nothing -> pure []
      Just iss ->
        let path = dir <> "/" <> iss <> ".jwk"
        in handle
          (\(_ :: SomeException) -> pure [])
          (pure . fromJust . decode <$> L.readFile path)
