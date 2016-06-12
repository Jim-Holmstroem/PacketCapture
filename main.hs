{-# LANGUAGE OverloadedStrings #-}

import Data.ByteString (ByteString(..))
import qualified Data.ByteString as BS

import Text.Printf

import Control.Monad
import System.Environment

import Network.Pcap

hex :: ByteString -> String
hex = concatMap (printf "%02x|") . BS.unpack

callback :: PktHdr -> ByteString -> IO ()
callback hdr payload = putStrLn $ take 128 $ hex payload


main :: IO ()
main = do
    interfaces <- findAllDevs
    -- putStrLn $ (++) "interfaces: " $ show $ map ifName $ interfaces

    (deviceName:_) <- getArgs

    pHandle <- openLive deviceName (2^16) False 0
    setDirection pHandle Out

    ifDatalink <- datalink pHandle

    swapped <- isSwapped pHandle
    putStrLn $ show swapped


    -- putStrLn $ "datalink: " ++ show ifDatalink

    -- putStrLn "====="

    -- void $ loopBS pHandle (-1) callback
