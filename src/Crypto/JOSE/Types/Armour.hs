-- Copyright (C) 2014  Fraser Tweedale
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

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE UndecidableInstances #-}

{-|

Implementation of "armoured values" with partial decoding.

For cases where a value is parsed from some representation, but the
precise representation that was used is also needed.  The original
representation of a parsed value can be accessed using the 'armour'
function, but it cannot be changed.

-}
module Crypto.JOSE.Types.Armour
  (
    Armour(Unarmoured)
  , FromArmour(..)
  , ToArmour(..)
  , decodeArmour
  , armour
  , value
  ) where

import Control.Applicative
import Control.Monad ((>=>))

import Control.Lens
import Data.Aeson


-- | A value that can be "armoured", where the armour representation
-- is preserved when the value is parsed.
--
data Armour a b
  = Armoured a b
  | Unarmoured b
  deriving (Show)

instance Eq b => Eq (Armour a b) where
  a == b = a ^. value == b ^. value

-- | Lens for the unarmoured value.
--
value :: Lens' (Armour a b) b
value = lens (\case Armoured _ b -> b ; Unarmoured b -> b) (const Unarmoured)

-- | 'Getter' for the armour encoding.  If the armour was
-- remembered, it is returned unchanged.
--
armour :: ToArmour a b => Getter (Armour a b) a
armour = to (\case Armoured a _ -> a ; Unarmoured b -> toArmour b)


-- | Decoding from armoured representation.
--
class FromArmour a e b | a b -> e where
  parseArmour :: a -> Either e b


-- | Serialising to armoured representation.
--
class ToArmour a b where
  toArmour :: b -> a


-- | Decode an armoured value, remembering the armour.
--
decodeArmour :: FromArmour a e b => a -> Either e (Armour a b)
decodeArmour a = Armoured a <$> parseArmour a


instance (FromJSON a, Show e, FromArmour a e b) => FromJSON (Armour a b) where
  parseJSON = parseJSON >=> either (fail . show) pure . decodeArmour
