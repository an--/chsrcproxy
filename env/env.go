package env

import (
	"chsrcproxy/log"
	"chsrcproxy/protocol"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"net"
	"os"
)

const (
	ModeRelay = "relay"
	ModeEnd   = "end"
)

// 运行环境信息
type Env struct {
	Mode     string
	DstProto string

	RemoteAddr string
	RemotePort int

	ListenIP   string
	ListenPort int

	cacertPemPath string
	certPemPath   string
	priKeyPemPath string

	CACertPemB      *pem.Block
	LocalPriKeyPemB *pem.Block
	LocalCertPemB   *pem.Block
}

var runEnv = Env{}

func GetEnv() Env {
	return runEnv
}

// 处理 命令行参数
func CommadLineArgs() {
	flag.StringVar(&runEnv.Mode, "mode", "", "app run mode")
	flag.StringVar(&runEnv.RemoteAddr, "remoteAddr", "remoteAddr", "destination remote IP address")
	flag.IntVar(&runEnv.RemotePort, "remotePort", 0, "destination remote TCP port")
	flag.StringVar(&runEnv.ListenIP, "listenIP", "", "local listen IP address")
	flag.IntVar(&runEnv.ListenPort, "listenPort", 0, "local listen TCP port")

	flag.StringVar(&runEnv.cacertPemPath, "cacertpem", "", "ca cert")
	flag.StringVar(&runEnv.certPemPath, "certpem", "", "local public cert")
	flag.StringVar(&runEnv.priKeyPemPath, "prikeypem", "", "local private key")

	flag.Parse()

}

func EnvCheck() error {
	var remoteAddr = runEnv.RemoteAddr
	var remotePort = runEnv.RemotePort
	// 是否需要指定出口端目的地址
	var needRemote bool
	if "" == runEnv.Mode {
		runEnv.Mode = ModeEnd
	}
	if ModeEnd == runEnv.Mode {
		needRemote = false
		runEnv.DstProto = protocol.TCPType
	} else if ModeRelay == runEnv.Mode {
		needRemote = true
		runEnv.DstProto = protocol.CHSRCType
	} else {
		return errors.New("mode(" + runEnv.Mode + ") undefined")
	}

	if "" == runEnv.ListenIP {
		runEnv.ListenIP = "0.0.0.0"
		log.Infofln("listenIp is empty, use 0.0.0.0")
	}

	if ip := net.ParseIP(runEnv.ListenIP); nil == ip {
		return errors.New("listenIP(" + runEnv.ListenIP + ") is not ip address")
	}

	if runEnv.ListenPort <= 1024 || runEnv.ListenPort > 65535 {
		log.Infofln("listenPort(%v) is illegal, use default(%v)", runEnv.ListenPort, protocol.CHSRCDefPort)
		runEnv.ListenPort = protocol.CHSRCDefPort
	}

	if needRemote {
		if ip := net.ParseIP(remoteAddr); nil == ip {
			return errors.New("remoteAddr(" + remoteAddr + ") is not ip address")
		}
		// 如果 remotePort 错误，设置默认的 chsrc 目标端口
		if remotePort <= 1024 || remotePort > 65535 {
			log.Infofln("remotePort(%v) is illegal, use default(%v)", remotePort, protocol.CHSRCDefPort)
			runEnv.ListenPort = protocol.CHSRCDefPort
		}
	}

	if _, serr := os.Stat(runEnv.cacertPemPath); nil != serr {
		log.Panicf("cacertpem is not file path, path = %v", runEnv.cacertPemPath)
	}
	if _, serr := os.Stat(runEnv.certPemPath); nil != serr {
		log.Panicf("certPemPath is not file path, path = %v", runEnv.certPemPath)
	}
	if _, serr := os.Stat(runEnv.priKeyPemPath); nil != serr {
		log.Panicf("priKeyPemPath is not file path, path = %v", runEnv.priKeyPemPath)
	}

	var cacertPemB, caerr = readPemFile(runEnv.cacertPemPath)
	if nil != caerr {
		return caerr
	}
	var certPemB, certerr = readPemFile(runEnv.certPemPath)
	if nil != certerr {
		return certerr
	}

	var priKeyPemB, pkerr = readPemFile(runEnv.priKeyPemPath)
	if nil != pkerr {
		return pkerr
	}
	runEnv.CACertPemB = cacertPemB
	runEnv.LocalCertPemB = certPemB
	runEnv.LocalPriKeyPemB = priKeyPemB

	return nil
}

func readPemFile(path string) (*pem.Block, error) {
	var bs, rerr = ioutil.ReadFile(path)
	if nil != rerr {
		return nil, rerr
	}
	var block, _ = pem.Decode(bs)
	if nil == block {
		return nil, errors.New("file is not pem")
	}
	return block, nil
}
