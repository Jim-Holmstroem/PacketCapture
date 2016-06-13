{-# LANGUAGE OverloadedStrings #-}

import Control.Monad

import Data.ByteString (ByteString(..))
import Data.ByteString.Lazy (fromStrict, toStrict)
import qualified Data.ByteString as BS

import Data.Binary.Get
import Data.Word

import Text.Printf

import System.Environment

import Network.Pcap

data IPVersion = IPv4 | IPv6 deriving (Show, Eq)

--data Packet = Packet
--    { --version :: !IPVersion
--     internetHeaderLength :: !Word8 -- header length in 32byte words
--    } deriving (Show, Eq)

-- getPacket :: Get Word16
getPacket = do
    a <- getWord8
    a' <- getWord8
    length <- getWord16le
    identification <- getWord16le
    b <- getWord16le
    c <- getWord16le
    checksum <- getWord16le
    sourceAddress <- getWord32le
    destinationAddress <- getWord32le

    -- variable length IP Options (pretty uncommon)

    sourcePort <- getWord16le
    destinationPort <- getWord16le
    sequenceNumber <- getWord32le
    acknowledgementNumber <- getWord32le

    -- return $! (printf "%16b" identification :: String)
    return $! (sourcePort, destinationPort, sequenceNumber, acknowledgementNumber)


hex :: ByteString -> String
hex = concatMap (printf "%02x|") . BS.unpack

callback :: PktHdr -> ByteString -> IO ()
-- callback hdr payload = putStrLn $ take 128 $ hex payload
callback hdr payload = do
    putStrLn $ show $ runGet getPacket $ fromStrict payload

main :: IO ()
main = do
    interfaces <- findAllDevs
    -- putStrLn $ (++) "interfaces: " $ show $ map ifName $ interfaces

    (deviceName:_) <- getArgs

    pHandle <- openLive deviceName (2^16) False 0
    setDirection pHandle InOut

    ifDatalink <- datalink pHandle

    swapped <- isSwapped pHandle
    -- putStrLn $ show swapped


    -- putStrLn $ "datalink: " ++ show ifDatalink

    -- putStrLn "====="

    void $ loopBS pHandle (-1) callback
