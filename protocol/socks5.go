package protocol

import (
	"chsrcproxy/log"
	"errors"
	"fmt"
	"io"
	"net"
)

func accept(conn net.Conn) {

}

// AcceptSOCKS5Method 处理 SOKS5 协议第一个请求
// 返回 bool, true 当前实现能够处理，可以继续下一步，
// false 不能处理，马上关闭连接
func AcceptSOCKS5Method(conn net.Conn, bs []byte) error {
	// request version, methods
	var nmethods = bs[1]
	var methods = bs[2 : 2+nmethods]
	var noAuth = byte(0)

	// 查找无需认证的方法
	var foundNoAuth bool
	for _, v := range methods {
		if noAuth == v {
			foundNoAuth = true
			break
		}
	}

	//  如果找到 不需要认证的方法，响应 {5, 0}，否则响应 {5, 255}
	var methodResps = [2]byte{5, 255}
	if !foundNoAuth {
		ConnWriteLogErr(conn, methodResps[:])
		return errors.New("could not found method")
	} else {
		methodResps[1] = 0
		ConnWriteLogErr(conn, methodResps[:])
		return nil
	}
}

// TransTCPData 转发数据
func TransTCPData(srcConn, dstConn net.Conn) {
	var dcErrChan = make(chan *error)
	var cdErrChan = make(chan *error)
	var dstAddrStr, srcAddrStr = dstConn.RemoteAddr(), srcConn.RemoteAddr()

	go ioCopyRChan(dstConn, srcConn, dcErrChan)
	go ioCopyRChan(srcConn, dstConn, cdErrChan)

	log.Infof("src: %v, dst: %v, connect success", srcAddrStr, dstAddrStr)

	dcErr := <-dcErrChan
	cdErr := <-cdErrChan
	if nil != *dcErr {
		log.Errorf("dst(%v) copy to src(%v) error = %v", dstAddrStr, srcAddrStr, dcErr)
	}
	if nil != *cdErr {
		log.Errorf("src(%v) copy to dst(%v) error = %v", srcAddrStr, dstAddrStr, cdErr)
	}
	if nil == *dcErr && nil == *cdErr {
		log.Infof("src(%v) copy to dst(%v) completed, close...", srcAddrStr, dstAddrStr)
	}
}

// 将 iocopy 返回的 err 写入 channel，用于获取 iocopy 执行完成的信息
func ioCopyRChan(dstConn, srcConn net.Conn, errChan chan *error) {
	var _, err = io.Copy(dstConn, srcConn)
	errChan <- &err
}

// AcceptSocks5TCPConnect 处理 socks5 tcp connect 请求
// 成功连接返回 true 否则返回 false
func AcceptSocks5TCPConnect(srcConn net.Conn) (*NetAddr, error) {
	var rbuf [1024]byte
	var netType string
	var dstAddr string
	var dstPort int
	var dstAddrBs []byte
	if _, _, rerr := ConnReadLogErr(srcConn, rbuf[:]); nil != rerr {
		return nil, rerr
	}

	if SOCKS5Ver != rbuf[0] {
		var errMsg = fmt.Sprintf("first byte = %v", rbuf[0])
		return nil, errors.New(errMsg)
	}

	if SOCKS5CmdConn != rbuf[1] {
		var errMsg = fmt.Sprintf("CMD = %v, not 1 (CONNECT)", rbuf[1])
		var soks5Resp = buildTCPConnectResp(SOCKS5RepCmdNotsup, rbuf[3], (&[1]byte{0})[:], 0)
		ConnWriteLogErr(srcConn, soks5Resp)
		return nil, &ProtError{"SOCKS5", SOCKS5RepCmdNotsup, errors.New(errMsg)}
	}

	if SOCKS5RSV != rbuf[2] {
		var errMsg = fmt.Sprintf("CMD = %v, not 0", rbuf[1])
		var soks5Resp = buildTCPConnectResp(SOCKS5RepCmdNotsup, rbuf[3], (&[1]byte{0})[:], 0)
		ConnWriteLogErr(srcConn, soks5Resp)
		return nil, &ProtError{"SOCKS5", 7, errors.New(errMsg)}
	}

	// destination address , port
	netType, dstAddr, dstPort, dstAddrBs, _ = getAddrPort(rbuf[:])
	if nil == dstAddrBs {
		var errMsg = fmt.Sprintf("SOCKS5 ATYPE not recognized")
		var soks5Resp = buildTCPConnectResp(SOCKS5RepAddrNotSup, rbuf[3], (&[1]byte{0})[:], 0)
		ConnWriteLogErr(srcConn, soks5Resp)
		return nil, &ProtError{"SOCKS5", SOCKS5RepAddrNotSup, errors.New(errMsg)}
	}

	// resp SOKS5 CONNECT
	var respBs = buildTCPConnectResp(SOCKS5RepSuc, rbuf[3], dstAddrBs, dstPort)
	if _, swErr := ConnWriteLogErr(srcConn, respBs); nil != swErr {
		return nil, swErr
	}

	return &NetAddr{
		AType: netType,
		Addr:  dstAddr,
		Port:  uint16(dstPort),
	}, nil
}

// 从 SOCKS5 CONNECT 的报文中获取 address type, address, port
func getAddrPort(bs []byte) (atype, addrStr string, portI int, addr, port []byte) {
	switch bs[3] {
	case 1:
		atype = "tcp"
		addr = bs[4:8]
		addrStr = net.IPv4(bs[4], bs[5], bs[6], bs[7]).String()
		port = bs[8:10]
	case 3:
		atype = "tcp"
		var domainL = int(bs[4])
		addr = bs[5 : 5+domainL]
		addrStr = string(bs[5 : 5+domainL])
		port = bs[5+domainL : 7+domainL]
	case 4:
		atype = "tcp"
		addr = bs[4:20]
		port = bs[20:22]
		var ip = make(net.IP, net.IPv6len)
		copy(ip, bs[4:20])
		addrStr = ip.String()
	default:
		return "", "", 0, nil, nil
	}
	portI = int(port[0])<<8 | int(port[1])
	return atype, addrStr, portI, addr, port
}

// 组装 SOCKS5 返回内容
func buildTCPConnectResp(rep byte, atype byte, addr []byte, port int) []byte {
	var respBs []byte
	respBs = (&[4]byte{SOCKS5Ver, rep, SOCKS5RSV, atype})[:]
	if nil != addr {
		for _, v := range addr {
			respBs = append(respBs, v)
		}
	}

	if 0 < port {
		respBs = append(respBs, byte(port))
		respBs = append(respBs, byte(port>>8))
	}
	return respBs
}
