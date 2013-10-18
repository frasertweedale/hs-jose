-- This file is part of jose - web crypto library
-- Copyright (C) 2013  Fraser Tweedale
--
-- jose is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

{-# LANGUAGE TemplateHaskell #-}

module Crypto.JOSE.TH where

import Control.Applicative
import Data.Aeson
import Data.Char
import Language.Haskell.TH.Lib
import Language.Haskell.TH.Syntax


capitalize :: String -> String
capitalize (x:xs) = toUpper x:xs
capitalize s = s

sanitize :: String -> String
sanitize = map (\c -> if isAlphaNum c then c else '_')

conize :: String -> Name
conize = mkName . capitalize . sanitize

guardPred :: String -> ExpQ
guardPred s = [e| $(varE $ mkName "s") == s |]

guardExp :: String -> ExpQ
guardExp s = [e| pure $(conE $ conize s) |]

guard :: String -> Q (Guard, Exp)
guard s = normalGE (guardPred s) (guardExp s)

endGuardPred :: ExpQ
endGuardPred = [e| otherwise |]

endGuardExp :: ExpQ
endGuardExp = [e| fail "unrecognised value" |]

endGuard :: Q (Guard, Exp)
endGuard = normalGE endGuardPred endGuardExp

guardedBody :: [String] -> BodyQ
guardedBody vs = guardedB (map guard vs ++ [endGuard])

parseJSONClauseQ :: [String] -> ClauseQ
parseJSONClauseQ vs = clause [varP $ mkName "s"] (guardedBody vs) []

parseJSONFun :: [String] -> DecQ
parseJSONFun vs = funD 'parseJSON [parseJSONClauseQ vs]


toJSONClause :: String -> ClauseQ
toJSONClause s = clause [conP (conize s) []] (normalB [| s |]) []

toJSONFun :: [String] -> DecQ
toJSONFun vs = funD 'toJSON (map toJSONClause vs)


aesonInstance :: String -> Name -> TypeQ
aesonInstance s n = appT (conT n) (conT $ mkName s)

deriveJOSEType :: String -> [String] -> Q [Dec]
deriveJOSEType s vs = sequenceQ [
  dataD (cxt []) (mkName s) [] (map conQ vs) (map mkName ["Eq", "Show"])
  , instanceD (cxt []) (aesonInstance s ''FromJSON) [parseJSONFun vs]
  , instanceD (cxt []) (aesonInstance s ''ToJSON) [toJSONFun vs]
  ]
  where
    conQ v = normalC (conize v) []
