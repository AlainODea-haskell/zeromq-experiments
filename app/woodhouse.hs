--  The Woodhouse Pattern
--
--  It may keep some malicious people out but all it takes is a bit
--  of network sniffing, and they'll be able to fake their way in.
--
--  More info: http://hintjens.com/blog:49#toc4

{-# LANGUAGE OverloadedStrings #-}
import Control.Concurrent (MVar, newMVar, newEmptyMVar, putMVar, takeMVar)
import Control.Exception (catch, IOException)
import Data.List (find, foldl')
import Data.List.NonEmpty (NonEmpty (..))
import Prelude hiding (catch)
import System.IO (hPutStr, stderr)
import System.ZMQ4.Monadic
import qualified System.ZMQ4.Internal as ZI
import qualified System.ZMQ4.Internal.Base as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8

main :: IO ()
main = runZMQ $ do
  --  Create and start authentication engine
  apiChan <- liftIO $ newEmptyMVar
  waitChan <- liftIO $ newEmptyMVar
  zauth apiChan waitChan
  liftIO $ putMVar apiChan ["VERBOSE"]
  liftIO $ takeMVar waitChan
  liftIO $ putMVar apiChan ["ALLOW", "127.0.0.1"]
  liftIO $ takeMVar waitChan

  --  Tell the authenticator how to handle PLAIN requests
  liftIO $ putMVar apiChan ["PLAIN", "passwords"]
  liftIO $ takeMVar waitChan

  --  Create and bind server socket
  server <- socket Push
  setPlainServer True server
  bind server "tcp://*:9000"

  --  Create and connect client socket
  client <- socket Pull
  setPlainUserName (restrict "admin") client
  setPlainPassword (restrict "secret") client
  connect client "tcp://127.0.0.1:9000"

  --  Send a single message from server to client
  send server [] "Hello"
  message <- receive client
  assert message (== "Hello")
  liftIO $ putStrLn "Woodhouse test OK"

  close client
  close server
  liftIO $ putMVar apiChan ["$TERM"]
  liftIO $ takeMVar waitChan

assert :: Monad m => a -> (a -> Bool) -> m a
assert x f | f x       = return x
           | otherwise = error "assertion failed!"

---- MISSING ZMQ API methods ----

-- | <http://api.zeromq.org/4-0:zmq-getsockopt zmq_getsockopt ZMQ_ZAP_DOMAIN>.
_setZapDomain :: BS.ByteString -> ZI.Socket a -> IO ()
_setZapDomain x s = ZI.setByteStringOpt s B.zapDomain x

setZapDomain :: BS.ByteString -> Socket z t -> ZMQ z ()
setZapDomain a = liftIO . _setZapDomain a . ZI.toSocket

---- MISSING ZMQ API methods ----


zauth :: MVar [BS.ByteString] -> MVar () -> ZMQ z ()
zauth apiChan waitChan = do
  verboseM <- liftIO $ newMVar False
  whitelistM <- liftIO $ newMVar []
  blacklistM <- liftIO $ newMVar []
  passwordsM <- liftIO $ newMVar []
  async $ liftIO $ zapAPI apiChan waitChan verboseM whitelistM blacklistM passwordsM
  async $ zapServer verboseM whitelistM blacklistM passwordsM
  return ()

zapAPI :: MVar [BS.ByteString]
       -> MVar ()
       -> MVar Bool
       -> MVar [BS.ByteString]
       -> MVar [BS.ByteString]
       -> MVar [(BS.ByteString, BS.ByteString)]
       -> IO ()
zapAPI apiChan waitChan verboseM whitelistM blacklistM passwordsM = go ""
  where
    go "$TERM" = return ()
    go _ = do
      verbose <- takeMVar verboseM
      putMVar verboseM verbose
      (command:args) <- takeMVar apiChan
      putStrLn $ "zauth: API command=" ++ show command
      case command of
        "$TERM" ->
          pure ()
        "VERBOSE" -> do
          takeMVar verboseM
          putMVar verboseM True
        "ALLOW" -> do
          whitelist <- takeMVar whitelistM
          if verbose
            then mapM_ (\x -> putStrLn $ "zauth: - whitelisting ipaddress=" ++ show x) args
            else pure ()
          putMVar whitelistM $ whitelist ++ args
        "DENY" -> do
          blacklist <- takeMVar blacklistM
          if verbose
            then mapM_ (\x -> putStrLn $ "zauth: - blacklisting ipaddress=" ++ show x) args
            else pure ()
          putMVar blacklistM $ blacklist ++ args
        "PLAIN" -> do
          let [filename] = args
          let file = C8.unpack filename
          passwords <- catch (BS.readFile file)
                (\e -> do let err = show (e :: IOException)
                          if verbose
                            then putStrLn $ "zauth: could not load file=" ++ file
                            else pure ()
                          return "")
          let passwordsMap = map (\(x:y:[]) -> (x, y)) .
                             map (C8.split '=') .
                             C8.lines $ passwords
          takeMVar passwordsM
          putMVar passwordsM passwordsMap
        _ -> do
          putStrLn $ "zauth: - invalid command: " ++ show command
      putMVar waitChan ()
      go command

zapServer :: MVar Bool
          -> MVar [BS.ByteString]
          -> MVar [BS.ByteString]
          -> MVar [(BS.ByteString, BS.ByteString)]
          -> ZMQ z ()
zapServer verboseM whitelistM blacklistM passwordsM = do
  auth <- socket Rep
  bind auth "inproc://zeromq.zap.01"
  go auth
  where
    go :: (Sender t, Receiver t) => Socket z t -> ZMQ z ()
    go auth = do
      verbose <- liftIO $ takeMVar verboseM
      liftIO $ putMVar verboseM verbose
      msg@(version:sequence:domain:address:identity:mechanism:args) <- receiveMulti auth
      assert version (== "1.0")

      --  Check that the address is in the whitelist
      whitelist <- liftIO $ takeMVar whitelistM
      liftIO $ putMVar whitelistM whitelist
      (allowed, denied) <-
            if (not.null) whitelist
              then if address `elem` whitelist
                then do
                  if verbose
                    then liftIO $ putStrLn $ "zauth: - passed (whitelist) address=" ++ show address
                    else pure ()
                  return (True, False)
                else do
                  liftIO $ putStrLn $ "zauth: - denied (not in whitelist) address=" ++ show address
                  return (False, True)
              else do
                --  Check that the address is NOT in the blacklist
                blacklist <- liftIO $ takeMVar blacklistM
                liftIO $ putMVar blacklistM blacklist
                if (not.null) blacklist
                  then if address `elem` blacklist
                    then do
                      if verbose
                        then liftIO $ putStrLn $ "zauth: - denied (blacklist) address=" ++ show address
                        else pure ()
                      return (False, True)
                    else do
                      if verbose
                        then liftIO $ putStrLn $ "zauth: - passed (not in blacklist) address=" ++ show address
                        else pure ()
                      return (True, False)
                  else return (True, False)

      allowed' <-
        if not denied
          then case mechanism of
            "NULL" -> do
              if verbose
                then liftIO $ putStrLn $ "zauth: - allowed (NULL)"
                else pure ()
              return True
            "PLAIN" ->
              liftIO $ authenticatePlain args verbose passwordsM
            _ -> return False
          else pure allowed
      case allowed' of
        True -> do
          zapRequestReply auth sequence "200" "OK"
        False -> do
          zapRequestReply auth sequence "400" "No access"
      go auth

authenticatePlain :: [BS.ByteString]
                  -> Bool
                  -> MVar [(BS.ByteString, BS.ByteString)]
                  -> IO Bool
authenticatePlain (username:password:[]) verbose passwordsM = do
  passwords <- takeMVar passwordsM
  putMVar passwordsM passwords
  if null passwords
    then do
      putStrLn $ "zauth: - denied (PLAIN) no password file defined"
      return False
    else if go $ find ((== username).fst) passwords
      then do
        if verbose
          then
            --  NOTE: it's a REALLY bad idea to log passwords
            --
            --  Logging here consistent with CZMQ 4.0.2 zauth implementation:
            --  https://github.com/zeromq/czmq/blob/v4.0.2/src/zauth.c#L341-L365
            putStrLn $ "zauth: - allowed (PLAIN) username=" ++
                       show username ++ " password=" ++ show password
          else pure ()
        return True
      else do
        if verbose
          then putStrLn $ "zauth: - denied (PLAIN) username=" ++
                          show username ++ " password=" ++ show password
          else pure ()
        return False

  where go Nothing = False -- user doesn't exist
        go (Just (u, p)) =
          username == u &&
          -- CZMQ does streq which fails fast and is vulnerable to
          -- side-channel attacks based on timing
          -- Resist timing attacks by using constant-time comparison
          password `constantEq` p

constantEq :: BS.ByteString -> BS.ByteString -> Bool
constantEq xs ys =
  BS.length xs == BS.length ys &&
  BS.length xs == (foldl' (\acc x -> if x then acc + 1 else acc) 0 $
                   map (\(x,y) -> x == y) $ BS.zip xs ys)

zapRequestReply :: Sender t => Socket z t -> BS.ByteString -> BS.ByteString -> BS.ByteString -> ZMQ z ()
zapRequestReply auth sequence statusCode statusText = do
  sendMulti auth $ "1.0" :|
    [ sequence
    , statusCode
    , statusText
    , ""
    , ""
    ]
