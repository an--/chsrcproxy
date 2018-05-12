package protocol

import (
	"chsrcproxy/log"
	"fmt"
	"io"
	"net"
	"time"
)

type NetAddr struct {
	AType string
	Addr  string
	Port  uint16
}

func (netAddr *NetAddr) HostStr() string {
	var portStr = fmt.Sprintf("%d", netAddr.Port)
	return net.JoinHostPort(netAddr.Addr, portStr)
}

// ProtError  协议错误
type ProtError struct {
	Protocol string
	ErrorNum byte
	Err      error
}

func (e *ProtError) Error() string {
	return fmt.Sprintf("protocol %v, %v", e.Protocol, e.Err.Error())
}

// 默认 tcp 建立连接的超时时间
var tcpCTimeOut = 1 * time.Second

// ConnReadLogErr 从 net.Conn 读取数据，出错时日志记录
func ConnReadLogErr(conn net.Conn, bs []byte) (rn int, isEOF bool, err error) {
	rn, err = conn.Read(bs)
	if nil != err {
		log.Errorf("conn read error = %v, remoteAddr = %v \n", err, conn.RemoteAddr())
		return rn, "EOF" == err.Error(), err
	}
	return rn, false, nil
}

// ConnWriteLogErr 向 net.Conn 写入数据，出错时日志记录
func ConnWriteLogErr(conn net.Conn, bs []byte) (wn int, err error) {
	wn, err = conn.Write(bs)
	if nil == err && wn != len(bs) {
		err = io.ErrShortWrite
	}
	if nil != err {
		log.Errorf("conn write error = %v, remoteAddr = %v \n", err, conn.RemoteAddr())
	}
	return wn, err
}

// ConnCloseLog log close
func ConnCloseLog(conn net.Conn) (err error) {
	if nil != conn {
		log.Infofln("connect colse, src.addr = %s , remote.addr = %s", conn.LocalAddr().String(), conn.RemoteAddr().String())
		err = conn.Close()
	}
	return err
}

// ProtExchange 转发数据时协议切换处理
func ProtExchange(srcConn net.Conn, outProto, outAddr string, outPort int) {
	defer ConnCloseLog(srcConn)

	var rbuf [6]byte
	if _, _, rerr := ConnReadLogErr(srcConn, rbuf[:]); nil != rerr {
		return
	}
	log.Debugfln("srcConn first 6 bytes = %v", rbuf[:6])

	var dstConn net.Conn
	var dialErr error
	defer ConnCloseLog(dstConn)

	var oPortStr = fmt.Sprintf("%d", outPort)
	if CHSRCType == string(rbuf[:5]) {
		// chsrc
		log.Infofln("srcConn is chsrc srcConnection")
		var srcChsrcC = ChsrcConn{
			TCPConn: srcConn,
			Seq:     1,
		}

		if err := srcChsrcC.Accept(); nil != err {
			log.Errorf("accept chsrc connection error = %v", err)
			return
		}

		if TCPType == outProto {
			var dstPort = fmt.Sprintf("%d", srcChsrcC.DSTPort)
			var addrStr = net.JoinHostPort(srcChsrcC.DSTAddr, dstPort)
			dstConn, dialErr = net.DialTimeout(srcChsrcC.DSTAType, addrStr, tcpCTimeOut)
			if nil != dialErr {
				log.Errorf("dial conntion error = %v", dialErr)
				return
			}
			defer ConnCloseLog(dstConn)

			var ch = TCPChsrcChannel{
				TCPConn:   &dstConn,
				ChsrcConn: &srcChsrcC,
			}
			if terr := ch.Trans(); nil != terr {
				log.Errorfln("chsrc connection to tcp connection error = %v", terr)
				return
			}
			log.Errorfln("chsrc to tcp complete, chsrc.remote = %v, tcp.remote = %v", srcChsrcC.TCPConn.RemoteAddr, dstConn.RemoteAddr)
		} else if CHSRCType == outProto {
			dstConn, dialErr = net.DialTimeout(TCPType, net.JoinHostPort(outAddr, oPortStr), tcpCTimeOut)
			if nil != dialErr {
				log.Errorf("dial conntion error = %v", dialErr)
				return
			}
			defer ConnCloseLog(dstConn)

			var dstChsrcC = ChsrcConn{
				TCPConn: dstConn,
				Seq:     0,
			}
			if cerr := dstChsrcC.Connect(); nil != cerr {
				log.Errorfln("chsrc connect  error = %v", cerr)
				return
			}
			var ch = ChsrcChannel{
				SrcConn: &srcChsrcC,
				DstConn: &dstChsrcC,
			}
			if terr := ch.Trans(); nil != terr {
				log.Errorfln("chsrc connection to chsrc tcp connection error = %v", terr)
				return
			}
		} else {
			log.Errorfln("out protocol not support")
			return
		}
	} else if SOCKS5Ver == rbuf[0] {
		// socks5
		log.Infofln("srcConn is socks5 srcConnection")
		var reqBs []byte
		var methodLen = rbuf[1]
		copy(reqBs[:], rbuf[:])
		if 3 < methodLen {
			var buf [255]byte
			srcConn.Read(buf[:])
			for i := byte(0); i < methodLen-3; i++ {
				reqBs = append(reqBs, buf[i])
			}
		}
		if err := AcceptSOCKS5Method(srcConn, rbuf[:]); nil != err {
			log.Errorfln("SOCKS5 error = %c", err)
			return
		}
		var dstAddr, cerr = AcceptSocks5TCPConnect(srcConn)
		if nil != cerr {
			log.Errorfln("SOCKS5 connect error = %v", cerr)
			return
		}

		if TCPType == outProto {
			var dstHostStr = dstAddr.HostStr()
			dstConn, dialErr = net.DialTimeout(dstAddr.AType, dstHostStr, tcpCTimeOut)
			if nil != dialErr {
				log.Errorfln("connect destination address error = %v", dialErr)
				return
			}
			defer ConnCloseLog(dstConn)

			TransTCPData(srcConn, dstConn)
		} else if CHSRCType == outProto {
			dstConn, dialErr = net.DialTimeout(TCPType, net.JoinHostPort(outAddr, oPortStr), tcpCTimeOut)
			if nil != dialErr {
				log.Errorf("dial conntion error = %v", dialErr)
				return
			}
			defer ConnCloseLog(dstConn)
			var dstChsrcC = ChsrcConn{
				TCPConn:  dstConn,
				Seq:      0,
				DSTAType: dstAddr.AType,
				DSTAddr:  dstAddr.Addr,
				DSTPort:  dstAddr.Port,
			}
			if cerr := dstChsrcC.Connect(); nil != cerr {
				log.Errorfln("chsrc connect  error = %v", cerr)
				return
			}

			var ch = TCPChsrcChannel{
				TCPConn:   &srcConn,
				ChsrcConn: &dstChsrcC,
			}
			if terr := ch.Trans(); nil != terr {
				log.Errorfln("tcp connection to chsrc  connection error = %v", terr)
				return
			}
		} else {
			log.Errorfln("out protocol not support")
			return
		}
	}
}
