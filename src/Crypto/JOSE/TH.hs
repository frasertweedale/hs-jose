-- Copyright (C) 2013, 2014, 2016  Fraser Tweedale
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

{-# LANGUAGE CPP #-}
{-# LANGUAGE TemplateHaskell #-}

{-|

Template Haskell shorthand for deriving the /many/ nullary JOSE
data constructors and associated Aeson instances.

-}

module Crypto.JOSE.TH
  (
    deriveJOSEType
  ) where

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

-- | Expression for an end guard.  Arg describes type it was expecting.
--
endGuardExp :: String -> ExpQ
endGuardExp s = [e| fail ("unrecognised value; expected: " ++ s) |]

-- | Build a catch-all guard that fails.  String describes what is expected.
--
endGuard :: String -> Q (Guard, Exp)
endGuard s = normalGE endGuardPred (endGuardExp s)

guardedBody :: [String] -> BodyQ
guardedBody vs = guardedB (map guard vs ++ [endGuard (show vs)])

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

-- | Derive a JOSE sum type with nullary data constructors, along
-- with 'ToJSON' and 'FromJSON' instances
--
deriveJOSEType
  :: String
  -- ^ Type name.
  -> [String]
  -- ^ List of JSON string values.  The corresponding constructor
  -- is derived by upper-casing the first letter and converting
  -- non-alpha-numeric characters are converted to underscores.
  -> Q [Dec]
deriveJOSEType s vs = sequenceQ [
  let
    derive = map mkName ["Eq", "Ord", "Show"]
  in
#if ! MIN_VERSION_template_haskell(2,11,0)
    dataD (cxt []) (mkName s) [] (map conQ vs) derive
#elif ! MIN_VERSION_template_haskell(2,12,0)
    dataD (cxt []) (mkName s) [] Nothing (map conQ vs) (mapM conT derive)
#else
    dataD (cxt []) (mkName s) [] Nothing (map conQ vs) [return (DerivClause Nothing (map ConT derive))]
#endif
  , instanceD (cxt []) (aesonInstance s ''FromJSON) [parseJSONFun vs]
  , instanceD (cxt []) (aesonInstance s ''ToJSON) [toJSONFun vs]
  ]
  where
    conQ v = normalC (conize v) []
