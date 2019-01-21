{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module WrappedExceptT where

import Control.Monad.Except
import Control.Monad.Trans (MonadTrans(..))
import Crypto.Random (MonadRandom(..))

newtype WrappedExceptT e f a =
  WrappedExceptT { runWrappedExceptT :: ExceptT e f a }
  deriving (Eq, Ord, Show, Functor, Applicative, Monad, MonadTrans)

instance MonadRandom f => MonadRandom (WrappedExceptT e f) where
  getRandomBytes = lift . getRandomBytes

instance Monad f => MonadError e (WrappedExceptT e f) where
  throwError =
    WrappedExceptT . throwError 
  catchError (WrappedExceptT a) f =
    WrappedExceptT (catchError a (runWrappedExceptT . f))
    
runWrappedExceptT' ::
  WrappedExceptT e f a
  -> f (Either e a)
runWrappedExceptT' =
  runExceptT . runWrappedExceptT
