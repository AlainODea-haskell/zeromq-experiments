--  The Grasslands Pattern
--
--  The Classic ZeroMQ model, plain text with no protection at all.
--
--  More info: http://hintjens.com/blog:49#toc2

{-# LANGUAGE OverloadedStrings #-}
import System.ZMQ4.Monadic

main :: IO ()
main = runZMQ $ do
  --  Create and bind server socket
  server <- socket Push
  bind server "tcp://*:9000"

  --  Create and connect client socket
  client <- socket Pull
  connect client "tcp://127.0.0.1:9000"

  --  Send a single message from server to client
  send server [] "Hello"
  message <- receive client
  assert message (== "Hello")
  liftIO $ putStrLn "Grasslands test OK"

assert :: Monad m => a -> (a -> Bool) -> m a
assert x f | f x       = return x
           | otherwise = error "assertion failed!"
