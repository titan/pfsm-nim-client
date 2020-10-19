module NimClient

import Data.Maybe
import Data.List
import Data.List1
import Data.SortedMap
import Data.SortedSet
import Data.Strings
import System
import System.File

import Pfsm
import Pfsm.Analyser
import Pfsm.Checker
import Pfsm.Data
import Pfsm.Parser
import Pfsm.Nim

record AppConfig where
  constructor MkAppConfig
  src : String

indentDelta : Nat
indentDelta = 2

toNim : AppConfig -> Fsm -> IO ()
toNim conf fsm
  = let name = fsm.name
        pre = camelize name
        refs = liftReferences fsm.model in
        putStrLn $ generateClient pre name fsm refs
  where
    generateClient : String -> String -> Fsm -> List String -> String
    generateClient pre name fsm refs
      = join "\n\n" $ List.filter nonblank [ generateImports refs
                                           , generateTypes pre name fsm.model
                                           , generateJsonToRecords pre name fsm.model
                                           , generateJsonToObject pre name fsm.model
                                           , generateFetchLists pre name fsm.model fsm.states
                                           , generateEvents pre name fsm.events
                                           ]
      where
        generateImports : List String -> String
        generateImports refs
          = List.join "\n" [ "import hmac, httpclient, json, options, random, sequtils, strtabs, strutils, tables, test_helper, times"
                           , List.join "\n" $ map (("import " ++) . toNimName) refs
                           ]

        generateTypes : String -> String -> List Parameter -> String
        generateTypes pre name model
          = let rks = liftRecords model in
                join "\n" $ List.filter nonblank [ "type"
                                                 , generateRecords indentDelta rks
                                                 , (indent indentDelta) ++ pre ++ "* = ref object of RootObj"
                                                 , List.join "\n" $ map (generateParameter (indentDelta * 2)) (("fsmid", (TPrimType PTULong) , Nothing) :: model)
                                                 ]
          where
            generateParameter : Nat -> Parameter -> String
            generateParameter idt (n, t, ms)
              = case lookup "reference" ms of
                     Just (MVString ref) => (indent idt) ++ (toNimName n) ++ "*: " ++ (camelize ref)
                     _ => (indent idt) ++ (toNimName n) ++ "*: " ++ (toNimType t)

            generateRecords : Nat -> List Tipe -> String
            generateRecords idt ts
                = join "\n" $ filter nonblank $ map (generateRecord idt) ts
              where
                generateRecord : Nat -> Tipe -> String
                generateRecord idt (TRecord n ps) = List.join "\n" [ (indent idt) ++ (camelize n) ++ "* = ref object of RootObj"
                                                                   , join "\n" $ map (generateParameter (idt + indentDelta)) ps
                                                                   ]
                generateRecord idt _              = ""

        generateFromJson : Nat -> Parameter -> String
        generateFromJson idt (n, t, ms)
          = case lookup "reference" ms of
                 Just (MVString ref) => (indent idt) ++ (toNimName n) ++ " = json_to_" ++ (toNimName ref) ++ "(obj{\"" ++ n ++ "\"})"
                 _ => (indent idt) ++ (toNimName n) ++ " = " ++ (toNimFromJson ("obj{\"" ++ n ++ "\"}") t)

        generateJsonToRecords : String -> String -> List Parameter -> String
        generateJsonToRecords pre name model
          = let rks = liftRecords model in
              join "\n\n" $ List.filter nonblank $ map (generateJsonToRecord pre name) rks
          where
            generateJsonToRecord : String -> String -> Tipe -> String
            generateJsonToRecord pre name (TRecord n params)
              = List.join "\n" [ "proc json_to_" ++ (toNimName n) ++ "(obj: JsonNode): " ++ (camelize n) ++ " ="
                               , (indent indentDelta) ++ "let"
                               , List.join "\n" $ map (generateFromJson (indentDelta * 2)) params
                               , (indent indentDelta) ++ "result = " ++ (camelize n) ++ "(" ++ (List.join ", " (map (\(n, _, _) => (toNimName n) ++ ": " ++ (toNimName n)) params)) ++ ")"
                               ]
            generateJsonToRecord pre name _ = ""

        generateJsonToObject : String -> String -> List Parameter -> String
        generateJsonToObject pre name params
          = let params' = ("fsmid", TPrimType PTULong, Nothing) :: params in
                List.join "\n" [ "proc json_to_" ++ (toNimName name) ++ "*(obj: JsonNode): " ++ pre ++ " ="
                               , (indent indentDelta) ++ "let"
                               , List.join "\n" $ map (generateFromJson (indentDelta * 2)) params'
                               , (indent indentDelta) ++ "result = " ++ pre ++ "(" ++ (List.join ", " (map (\(n, _, _) => (toNimName n) ++ ": " ++ (toNimName n)) params')) ++ ")"

                               ]

        generateFetchLists : String -> String -> List Parameter -> List1 State -> String
        generateFetchLists pre name model states
          = List1.join "\n\n" $ map (generateFetchList pre name model) states
          where
            generateFetchList : String -> String -> List Parameter -> State -> String
            generateFetchList pre name model (MkState sname _ _ _)
              = List.join "\n" [ "proc get_" ++ (toNimName sname) ++ "_" ++ (toNimName name) ++ "_list*(self: Caller, offset: uint = 0, limit: uint = 10): seq[" ++ pre ++ "] ="
                               , (indent indentDelta) ++ "let"
                               , (indent (indentDelta * 2)) ++ "client = newHttpClient()"
                               , (indent (indentDelta * 2)) ++ "body = \"\""
                               , (indent (indentDelta * 2)) ++ "signbody = @[\"limit=\" & $limit, \"offset=\" & $offset].join(\"&\")"
                               , (indent (indentDelta * 2)) ++ "date = getTime().format(\"ddd, dd MMM yyyy HH:mm:ss \'GMT\'\", utc())"
                               , (indent (indentDelta * 2)) ++ "headers = newHttpHeaders({"
                               , (indent (indentDelta * 3)) ++ "\"Date\": date,"
                               , (indent (indentDelta * 3)) ++ "\"Authorization\": \"$1:$2\" % [self.appid, hmac.toHex(hmac_sha256(self.appkey, \"GET|/" ++ name ++ "/" ++ sname ++ "|\" & signbody & \"|\" & date))],"
                               , (indent (indentDelta * 3)) ++ "\"x-noise\": strutils.toHex(rand(uint64)),"
                               , (indent (indentDelta * 3)) ++ "\"x-token\": self.access_token,"
                               , (indent (indentDelta * 2)) ++ "})"
                               , (indent (indentDelta * 2)) ++ "response = client.request(\"http://$1:$2/" ++ name ++ "/" ++ sname ++ "?offset=$3&limit=$4\" % [self.host, $self.port, $offset, $limit], \"GET\", body, headers = headers)"
                               , (indent indentDelta) ++ "client.close"
                               , (indent indentDelta) ++ "if response.code == Http200:"
                               , (indent (indentDelta * 2)) ++ "let"
                               , (indent (indentDelta * 3)) ++ "respbody = response.body.parseJson"
                               , (indent (indentDelta * 3)) ++ "code = respbody{\"code\"}.getInt"
                               , (indent (indentDelta * 3)) ++ "payload = respbody{\"payload\"}"
                               , (indent (indentDelta * 2)) ++ "if code == 200:"
                               , (indent (indentDelta * 3)) ++ "for e in payload{\"data\"}:"
                               , (indent (indentDelta * 4)) ++ "result.add(json_to_" ++ (toNimName name) ++ "(e))"
                               , (indent (indentDelta * 2)) ++ "else:"
                               , (indent (indentDelta * 3)) ++ "result = @[]"
                               , (indent (indentDelta * 1)) ++ "else:"
                               , (indent (indentDelta * 2)) ++ "result = @[]"
                               ]

        generateEvents : String -> String -> List1 Event -> String
        generateEvents pre name evts
          = join "\n\n" $ map (generateEvent pre name) evts
          where
            generateEvent : String -> String -> Event -> String
            generateEvent pre name (MkEvent ename params metas)
              = let isCreator = (MVString "true") == (fromMaybe (MVString "false") $ lookup "creator" metas)
                    params' = if isCreator then params else ("fsmid", (TPrimType PTULong) , Nothing) :: (the (List Parameter) params)
                    query = (if isCreator then "\"/" ++ name ++ "/" ++ ename ++ "\"" else ("\"/" ++ name ++ "/\" & $fsmid & \"/" ++ ename ++ "\"")) in
                    List.join "\n" $ List.filter nonblank [ "proc " ++ (toNimName ename) ++ "*(self: Caller, " ++ (generateParametersSignature params') ++ "): " ++ (if isCreator then "Option[uint64]" else "bool") ++ " ="
                                                          , (indent indentDelta) ++ "let"
                                                          , (indent (indentDelta * 2)) ++ "client = newHttpClient()"
                                                          , (indent (indentDelta * 2)) ++ "date = getTime().format(\"ddd, dd MMM yyyy HH:mm:ss \'GMT\'\", utc())"
                                                          , generateSignatureBody (indentDelta * 2) params
                                                          , (indent (indentDelta * 2)) ++ "headers = newHttpHeaders({"
                                                          , (indent (indentDelta * 3)) ++ "\"Date\": date,"
                                                          , (indent (indentDelta * 3)) ++ "\"Authorization\": \"$1:$2\" % [self.appid, hmac.toHex(hmac_sha256(self.appkey, \"POST|\" & " ++ query ++ " & \"|\" & signbody & \"|\" & date))],"
                                                          , (indent (indentDelta * 3)) ++ "\"x-noise\": strutils.toHex(rand(uint64)),"
                                                          , (indent (indentDelta * 3)) ++ "\"x-token\": self.access_token,"
                                                          , (indent (indentDelta * 2)) ++ "})"
                                                          , (indent (indentDelta * 2)) ++ "body = newJObject()"
                                                          , List.join "\n" $ map (generateJsonInitializer indentDelta) params
                                                          , (indent (indentDelta * 1)) ++ "let response = client.request(\"http://$1:$2/" ++ name ++ "/" ++ (if isCreator then ename else "$3/" ++ ename) ++ "\" % [self.host, $self.port" ++ (if isCreator then "" else ", $fsmid") ++ "], \"POST\", $body, headers = headers)"
                                                          , (indent indentDelta) ++ "client.close"
                                                          , (indent indentDelta) ++ "if response.code == Http200:"
                                                          , (indent (indentDelta * 2)) ++ "let"
                                                          , (indent (indentDelta * 3)) ++ "respbody = response.body.parseJson"
                                                          , (indent (indentDelta * 3)) ++ "code = respbody{\"code\"}.getInt"
                                                          , (indent (indentDelta * 2)) ++ "if code == 200:"
                                                          , if isCreator then (indent (indentDelta * 3)) ++ "result = some[uint64](respbody{\"payload\"}.getStr.parseBiggestUInt)"  else (indent (indentDelta * 3)) ++ "result = respbody{\"payload\"}.getStr == \"Okay\""
                                                          , (indent (indentDelta * 2)) ++ "else:"
                                                          , if isCreator then (indent (indentDelta * 3)) ++ "result = none(uint64)" else (indent (indentDelta * 3)) ++ "result = false"
                                                          , (indent indentDelta) ++ "else:"
                                                          , if isCreator then (indent (indentDelta * 2)) ++ "result = none(uint64)" else (indent (indentDelta * 2)) ++ "result = false"
                                                          ]
              where
                generateParametersSignature : List Parameter -> String
                generateParametersSignature ps
                  = List.join ", " $ map (\(n, t, _) => (toNimName n) ++ ": " ++ (toNimType t)) ps

                generateJsonInitializer : Nat -> Parameter -> String
                generateJsonInitializer idt (n, _, _)
                  = (indent idt) ++ "body.add(\"" ++ n ++ "\", % " ++ (toNimName n) ++ ")"

                generateSignatureBody : Nat -> List Parameter -> String
                generateSignatureBody idt ps
                  = let items = map generateSignatureBody' $ sortBy (\(a, _, _), (b, _, _) => compare a b) ps in
                        if length items > Z
                           then (indent idt) ++ "signbody = @[" ++ (join ", " items) ++ "].join(\"&\")"
                           else (indent idt) ++ "signbody = \"\""
                  where
                    generateSignatureBody' : Parameter -> String
                    generateSignatureBody' (n, (TPrimType PTString), _) = "\"" ++ n ++ "=\" & " ++ (toNimName n)
                    generateSignatureBody' (n, (TList _), _)            = "\"" ++ n ++ "=\" & $ %" ++ (toNimName n)
                    generateSignatureBody' (n, (TDict _ _), _)          = "\"" ++ n ++ "=\" & $ %" ++ (toNimName n)
                    generateSignatureBody' (n, _,                    _) = "\"" ++ n ++ "=\" & $ " ++ (toNimName n)

doWork : AppConfig -> IO ()
doWork conf
  = do Right content <- readFile conf.src
       | Left err => putStrLn $ show err
       case loadFsm content of
            Left e => putStrLn e
            Right fsm => toNim conf fsm

parseArgs : List String -> Maybe AppConfig
parseArgs
  = parseArgs' Nothing
  where
    parseArgs' : Maybe String -> List String -> Maybe AppConfig
    parseArgs' Nothing    []        = Nothing
    parseArgs' (Just src) []        = Just (MkAppConfig src)
    parseArgs' _          (x :: xs) = parseArgs' (Just x) xs

usage : String
usage
  = List.join "\n" [ "Usage: pfsm-to-nim-client <src>"
                   ]

main : IO ()
main
  = do args <- getArgs
       case tail' args of
            Nothing => putStrLn usage
            Just args' => case parseArgs args' of
                               Just conf => doWork conf
                               Nothing => putStrLn usage
