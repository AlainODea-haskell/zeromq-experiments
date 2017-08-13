--  The Strawhouse Pattern
--
--  We allow or deny clients according to their IP address. It may kee
--  spammers and idiots away, but won't stop a real attacker for more
--  than a heartbeat.
--
--  More info: http://hintjens.com/blog:49#toc3

{-# LANGUAGE OverloadedStrings #-}
import Control.Concurrent (MVar, newMVar, newEmptyMVar, putMVar, takeMVar)
import Data.List.NonEmpty (NonEmpty (..))
import System.ZMQ4.Monadic
import qualified System.ZMQ4.Internal as ZI
import qualified System.ZMQ4.Internal.Base as B
import qualified Data.ByteString as BS

main :: IO ()
main = runZMQ $ do
  --  Start an authentication engine for this context. This engine
  --  allows or denies incoming connections (talking to the libzmq
  --  core over a protocol called ZAP).
  apiChan <- liftIO $ newEmptyMVar
  waitChan <- liftIO $ newEmptyMVar
  zauth apiChan waitChan

  --  Get some indication of what the authenticator is deciding

  --  Whitelist our address; any other address will be rejected
  --  Ex: try with ["127.0.0.2"] as the whitelist. It prevents the comms.
  --      Why? The client address 127.0.0.1 doesn't match.
  --  Ex: try with [] as the whitelist. It still allows it.
  --      Why? zapServer works like CZMQ zauth and fails open.
  --  Ex: try with the line below commented out. It blocks.
  --      Why? zapServer will block forever trying to read the empty
  --           allowed MVar.
  liftIO $ putMVar apiChan ["ALLOW", "127.0.0.1", "127.0.0.2"]
--  liftIO $ putMVar apiChan ["DENY", "127.0.0.1", "127.0.0.2"]
  liftIO $ takeMVar waitChan

  --  Create and bind server socket
  server <- socket Push
  --  NULL mechanism only uses ZAP if there's a domain defined
  --  See: https://github.com/zeromq/libzmq/blob/v4.2.2/src/null_mechanism.cpp#L56
  --  Ex: try with the line below commented out. It "works".
  --      Why? ZAP isn't used, so there's no auth enforced at all.
  --  Ex: try with the line below commented out, but with "127.0.0.2" as
  --      the whitelist. It "works".
  --      Why? ZAP isn't used, so there's no auth enforced at all.
  setZapDomain "global" server
  bind server "tcp://*:9000"

  --  Create and connect client socket
  client <- socket Pull
  connect client "tcp://127.0.0.1:9000"

  --  Send a single message from server to client
  send server [] "Hello"
  message <- receive client
  assert message (== "Hello")
  liftIO $ putStrLn "Strawhouse test OK"

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
  whitelistM <- liftIO $ newMVar []
  blacklistM <- liftIO $ newMVar []
  async $ liftIO $ zapAPI apiChan waitChan whitelistM blacklistM
  async $ zapServer whitelistM blacklistM
  return ()

zapAPI :: MVar [BS.ByteString]
       -> MVar ()
       -> MVar [BS.ByteString]
       -> MVar [BS.ByteString]
       -> IO ()
zapAPI apiChan waitChan whitelistM blacklistM = go ""
  where
    go "$TERM" = return ()
    go _ = do
      (command:args) <- takeMVar apiChan
      putStrLn $ "zauth: API command=" ++ show command
      case command of
        "ALLOW" -> do
          mapM_ (\x -> putStrLn $ "zauth: - whitelisting ipaddress=" ++ show x) args
          whitelist <- takeMVar whitelistM
          putMVar whitelistM $ whitelist ++ args
        "DENY" -> do
          mapM_ (\x -> putStrLn $ "zauth: - blacklisting ipaddress=" ++ show x) args
          blacklist <- takeMVar blacklistM
          putMVar blacklistM $ blacklist ++ args
        _ -> pure ()
      putMVar waitChan ()
      go command

zapServer :: MVar [BS.ByteString] -> MVar [BS.ByteString] -> ZMQ z ()
zapServer whitelistM blacklistM = do
  auth <- socket Rep
  bind auth "inproc://zeromq.zap.01"
  go auth
  where
    go :: (Sender t, Receiver t) => Socket z t -> ZMQ z ()
    go auth = do
      msg@(version:sequence:domain:address:identity:mechanism:rest) <- receiveMulti auth
      assert version (== "1.0")

      --  Check that the address is in the whitelist
      whitelist <- liftIO $ takeMVar whitelistM
      (allowed, denied) <-
            if (not.null) whitelist
              then if address `elem` whitelist
                then do
                  liftIO $ putStrLn $ "zauth: - passed (whitelist) address=" ++ show address
                  return (True, False)
                else do
                  liftIO $ putStrLn $ "zauth: - denied (not in whitelist) address=" ++ show address
                  return (False, True)
              else do
                --  Check that the address is NOT in the blacklist
                blacklist <- liftIO $ takeMVar blacklistM
                if (not.null) blacklist
                  then if address `elem` blacklist
                    then do
                      liftIO $ putStrLn $ "zauth: - denied (blacklist) address=" ++ show address
                      return (False, True)
                    else do
                      liftIO $ putStrLn $ "zauth: - passed (not in blacklist) address=" ++ show address
                      return (True, False)
                  else return (True, False)

      allowed' <-
        if not denied
          then if mechanism == "NULL" && not allowed
            then do
              liftIO $ putStrLn $ "zauth: - allowed (NULL)"
              return True
            else
              return allowed
          else pure allowed
      case allowed' of
        True -> do
          zapRequestReply auth sequence "200" "OK"
        False -> do
          zapRequestReply auth sequence "400" "No access"
      go auth

zapRequestReply :: Sender t => Socket z t -> BS.ByteString -> BS.ByteString -> BS.ByteString -> ZMQ z ()
zapRequestReply auth sequence statusCode statusText = do
  sendMulti auth $ "1.0" :|
    [ sequence
    , statusCode
    , statusText
    , ""
    , ""
    ]
