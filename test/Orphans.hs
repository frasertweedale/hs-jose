-- Copyright (C) 2014, 2015, 2016, 2020  Fraser Tweedale
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Orphans where

import Crypto.Random (MonadRandom(..))
import Control.Monad.Trans (MonadTrans(..))

instance (
    MonadRandom m
  , MonadTrans t
  , Functor (t m)
  , Monad (t m)
  ) => MonadRandom (t m) where
    getRandomBytes = lift . getRandomBytes
