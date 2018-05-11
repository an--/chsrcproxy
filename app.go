package main

import (
	"chsrcproxy/env"
	"chsrcproxy/listener"
	"chsrcproxy/log"
	"chsrcproxy/protocol"
	"fmt"
	"net"
)

func main() {
	fmt.Printf("chasrcproxy main \n")

	env.CommadLineArgs()
	if cherr := env.EnvCheck(); nil != cherr {
		log.Panicf("env check error = %v", cherr)
	}

	var runEnv = env.GetEnv()
	log.Infofln("mode = %v", runEnv.Mode)
	var initKeyErr = protocol.InitKeystore(runEnv.CACertPemB, runEnv.LocalPriKeyPemB, runEnv.LocalCertPemB)
	if nil != initKeyErr {
		log.Panicf("init keystore error = %v", initKeyErr)
	}
	if protocol.CHSRCType == runEnv.DstProto {
		log.Infofln("remoteAddr = %v, remotePort = %v", runEnv.RemoteAddr, runEnv.RemotePort)
	}

	var connHandler = AppConnHandler{runEnv.DstProto, runEnv.RemoteAddr, runEnv.RemotePort}
	listener.Listen(runEnv.ListenIP, runEnv.ListenPort, connHandler)
}

type AppConnHandler struct {
	dstProtocol string
	destAddr    string
	destPort    int
}

func (handler AppConnHandler) ConnHandle(conn net.Conn) {
	protocol.ProtExchange(conn, handler.dstProtocol, handler.destAddr, handler.destPort)
}
