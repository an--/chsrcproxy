package listener

import (
	"chsrcproxy/log"
	"fmt"
	"net"
)

type ConnHandler interface {
	ConnHandle(net.Conn)
}

func Listen(addr string, port int, connHandler ConnHandler) {
	if 1024 >= port {
		panic("port less than 1024")
	}

	var lnet = "tcp4"
	var addrport = fmt.Sprintf("%s:%v", addr, port)
	var listener, err = net.Listen(lnet, addrport)
	if nil != err {
		log.Panicf("net listion error, error = %v, net = %v, addr = %v, port = %v", err, lnet, addr, port)
	}
	defer listener.Close()

	for {
		var conn, err = listener.Accept()
		if nil != err {
			log.Panicf("accept connection err = %v, listioner = %v", err, listener)
		}
		log.Debugf("accept new connection")
		go connHandler.ConnHandle(conn)
	}
}
