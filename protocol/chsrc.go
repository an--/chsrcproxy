package protocol

import (
	"chsrcproxy/log"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// chsrc 协议
//
// 数据报文结构
// 第一个请求报文 以 "CHSRC" 五个字节开头,第六个字节为版本(只有第一个请求报文包含)。
// 所有数据内容使用 section 结构进行传输，DATA section 使用 AES 加密。
// 每个 section 分为三部分: | title(1字节) | content length(2字节, b[0] | b[1]<<8 ) | content |。
//
// 建立连接
// 请求方先发送 SEQ,CONNECT,ATYPE,ADDR,PORT,CERT;
// 之后被请求方返回 SEQ,CONNECT,CERT,SECRET;
// 收到 CERT 之后需要用本地 CA 进行验证
// 请求方 CERT 验证通过之后， SECRET 使用请求方公钥 RSA-OAEP 加密发送。
// 被请求方在发送 SECRET section 后默认连接已经建立;
// 请求方在收到 SECRET section 之后默认连接已经建立;
//
// 数据传输
// 对数据内容进行 AES 加密后放到 DATA section 中传输;
//

// chsrcConn  section title number
const (
	CONNECT = iota // connect 标识
	CERT           // 公钥证书
	SECRET         // aes 密钥
	SEQ            // seq
	ATYPE          // address type
	ADDR           // address
	PORT           // port
	DATA           // data
	CLOSE
)

// section title name
var titles = [...]string{"CONNECT", "CERT", "SECRET", "SEQ", "ATYPE", "ADDR", "PORT", "DATA", "CLOSE"}

// chsrcConn status
const (
	CONNECTING = iota
	CONNECTED
	CLOSING
	CLOSED
)

var randR = rand.Reader

var keyExLabel = []byte("keyExchange")

// ChsrcConn  协议 连接结构
type ChsrcConn struct {
	TCPConn net.Conn // tcp 连接
	Status  byte     // 连接状态
	Seq     uint32   // 当前连接中的序列号

	Secret   [16]byte          // 当前连接的会话密钥
	PeerCert *x509.Certificate // 连接另一端的证书

	DSTAType string // 目标地址类型
	DSTAddr  string // 目标地址
	DSTPort  uint16 // 目标地址端口
}

// Section  消息内容单元
type Section struct {
	TitleNum byte
	Title    string
	CtLen    int
	Content  []byte
}

func (conn *ChsrcConn) Connect() error {
	var preBs = buildPreBs()
	conn.Status = CONNECTING
	if _, err := ConnWriteLogErr(conn.TCPConn, preBs); nil != err {
		return err
	}

	if err := conn.sendChsrcHeader(); nil != err {
		return err
	}

	for {
		var respSect, rsErr = conn.ReadSection()
		if nil != rsErr {
			return rsErr
		}
		switch respSect.TitleNum {
		case SEQ:
			log.Debugfln("connect > seq section = %d", binary.LittleEndian.Uint16(respSect.Content))
		case CONNECT:
			log.Debugfln("connect > connect section")
		case CERT:
			var respCert, certErr = x509.ParseCertificate(respSect.Content)
			if nil != certErr {
				return errors.New("response cert parse error, error = " + certErr.Error())
			}
			conn.PeerCert = respCert
			log.Debugfln("connect > cert section")
		case SECRET:
			var plainBs, deErr = rsa.DecryptOAEP(sha256.New(), randR, localKeyStore.LocalPriKey, respSect.Content, keyExLabel)
			if nil != deErr {
				return errors.New("response secret decrypt error, error = " + deErr.Error())
			}
			copy(conn.Secret[:], plainBs[:16])
			conn.Status = CONNECTED
			goto CONNECTED
		default:
			return errors.New("connect response unexcepted section")
		}
	}

CONNECTED:
	log.Infof("chsrcConnection connectected , remote = %v", conn.TCPConn.RemoteAddr)
	return nil
}

func (conn *ChsrcConn) sendChsrcHeader() error {
	// SEQ section
	if err := conn.sendSeq(); nil != err {
		return err
	}

	// CONNECT section
	if _, err := conn.WriteSectionBs(CONNECT, []byte{}); nil != err {
		return err
	}

	// dst addr
	if err := conn.SendAddrPort(); nil != err {
		return err
	}

	// cert
	var localKeyStore = GetLocalKeyStore()
	if err := conn.SendCert(localKeyStore.LocalCert); nil != err {
		return err
	}

	return nil
}

// Accept connection
func (conn *ChsrcConn) Accept() error {
	for {
		var reqSect, rsErr = conn.ReadSection()
		if nil != rsErr {
			return rsErr
		}

		switch reqSect.TitleNum {
		case SEQ:
			log.Debugfln("accept > seq section = %d", binary.LittleEndian.Uint16(reqSect.Content))
			// SEQ section
			if err := conn.sendSeq(); nil != err {
				return err
			}
		case CONNECT:
			log.Debugfln("connect > connect section")
			if _, err := conn.WriteSectionBs(CONNECT, []byte{}); nil != err {
				return err
			}
		case ATYPE:
			log.Debugfln("accept > atype = %s", string(reqSect.Content))
			conn.DSTAType = string(reqSect.Content)
		case ADDR:
			log.Debugfln("accept > addr = %s", string(reqSect.Content))
			conn.DSTAddr = string(reqSect.Content)
		case PORT:
			log.Debugfln("accept > atype = %d", binary.LittleEndian.Uint16(reqSect.Content))
			conn.DSTPort = binary.LittleEndian.Uint16(reqSect.Content)
		case CERT:
			var certErr = conn.acceptCert(reqSect.Content)
			if nil != certErr {
				return errors.New("accept cert error, error = " + certErr.Error())
			}
			conn.Status = CONNECTED
			goto CONNECTED
		default:
			return errors.New("connect response unexcepted section")
		}
	}

CONNECTED:
	log.Infof("chsrcConnection connectected , remote = %v", conn.TCPConn.RemoteAddr)
	return nil
}

func (conn *ChsrcConn) acceptCert(certBs []byte) error {
	var reqCert, certErr = x509.ParseCertificate(certBs)
	if nil != certErr {
		return errors.New("response cert parse error, error = " + certErr.Error())
	}
	var localKeyStore = GetLocalKeyStore()
	var verifyOps = x509.VerifyOptions{
		Roots: localKeyStore.RootCertPool,
	}
	var _, verifyErr = reqCert.Verify(verifyOps)
	if nil != verifyErr {
		return verifyErr
	}

	conn.SendCert(localKeyStore.LocalCert)
	conn.PeerCert = reqCert

	// send aes key
	var aesKey = md5.Sum([]byte(time.Now().String()))
	copy(conn.Secret[:], aesKey[:16])
	conn.SendAESSecret(conn.Secret[:])

	log.Debugfln("connect > send cert section")
	return nil
}

// send seq section
func (conn *ChsrcConn) sendSeq() error {
	var seqBs [4]byte
	binary.LittleEndian.PutUint32(seqBs[:], conn.NextSeq())
	if _, err := conn.WriteSectionBs(SEQ, seqBs[:]); nil != err {
		return err
	}
	return nil
}

// sendClose send Close section
func (conn *ChsrcConn) sendClose() error {
	// Close section
	if _, err := conn.WriteSectionBs(CLOSE, []byte{}); nil != err {
		return err
	}
	return nil
}

// SendAddrPort 发送 目的地址端口
func (conn *ChsrcConn) SendAddrPort() error {

	var addrTypeSect = buildSection(ATYPE, []byte(conn.DSTAType))
	var addrSect = buildSection(ADDR, []byte(conn.DSTAddr))
	var portBs [2]byte
	binary.LittleEndian.PutUint16(portBs[:], conn.DSTPort)
	var portSect = buildSection(PORT, portBs[:])

	if _, err := conn.WriteSection(addrTypeSect); nil != err {
		return err
	}
	if _, err := conn.WriteSection(addrSect); nil != err {
		return err
	}
	if _, err := conn.WriteSection(portSect); nil != err {
		return err
	}
	return nil
}

// SendCert 将证书作为 section 发送
func (conn *ChsrcConn) SendCert(cert *x509.Certificate) error {
	if _, err := conn.WriteSectionBs(CERT, cert.Raw); nil != err {
		return err
	}
	return nil
}

// SendAESSecret 将 AES 密钥作为 section 发送
func (conn *ChsrcConn) SendAESSecret(secretBs []byte) error {
	var peerPubK, isRSAPubK = conn.PeerCert.PublicKey.(*rsa.PublicKey)
	if !isRSAPubK {
		return errors.New("SendAESSecret > PeerCert.PublicKey is not *rsa.PublicKey")
	}
	var cipherBs, enErr = rsa.EncryptOAEP(sha256.New(), randR, peerPubK, secretBs, keyExLabel)
	if nil != enErr {
		return enErr
	}

	if _, err := conn.WriteSectionBs(SECRET, cipherBs); nil != err {
		return err
	}
	return nil
}

// NextSeq 递增 seq
func (conn *ChsrcConn) NextSeq() uint32 {
	var seq = conn.Seq
	conn.Seq = seq + 2
	return seq
}

// ReadData 读取数据内容
func (conn *ChsrcConn) ReadData() ([]byte, error) {
	var section, rerr = conn.ReadSection()
	if nil != rerr {
		return nil, rerr
	}

	var plainBs, aesErr = AESCBCCodec(conn.Secret[:], section.Content, false)
	if nil != aesErr {
		return nil, aesErr
	}
	if DATA != section.TitleNum {
		return nil, errors.New("chsrc section is not DATA")
	}
	log.Debugfln("ReadData length = %d, content = %v", len(plainBs), string(plainBs))
	return plainBs, nil
}

// ReadSection 读取消息的下一个 Section
// 如果 tNum == DATA，对内容进行 AES 解密
func (conn *ChsrcConn) ReadSection() (section *Section, err error) {
	var rbuf = make([]byte, 3)
	var tcpConn = conn.TCPConn
	if _, err := io.ReadFull(tcpConn, rbuf[:]); nil != err {
		return nil, err
	}
	var tNum = rbuf[0]
	var ctLen = int(rbuf[1]) | int(rbuf[2])<<8
	var ctBs = make([]byte, ctLen)
	if 0 < ctLen {
		if _, err := io.ReadFull(tcpConn, ctBs); nil != err {
			return nil, err
		}
	}
	return buildSection(tNum, ctBs), nil
}

// WriteSection 向 tcp 连接中写入一个 Section 内容
func (conn *ChsrcConn) WriteSection(section *Section) (wn int, err error) {
	return conn.WriteSectionBs(section.TitleNum, section.Content)
}

// WriteData 写入数据内容
func (conn *ChsrcConn) WriteData(ctBs []byte) (wn int, err error) {
	var cipherBs, aesErr = AESCBCCodec(conn.Secret[:], ctBs, true)
	if nil != aesErr {
		return wn, aesErr
	}

	log.Debugfln("WriteData length = %d, content = %v", len(cipherBs), string(cipherBs))
	return conn.WriteSectionBs(DATA, cipherBs)
}

// WriteSectionBs 向 tcp 连接中写入一个 Section 内容
// 如果 tNum == DATA，对内容进行 AES 加密
func (conn *ChsrcConn) WriteSectionBs(tNum byte, ctBs []byte) (wn int, err error) {
	var contentBs = ctBs

	var ctLen = len(contentBs)
	var ctHeaderBs = [3]byte{tNum, byte(ctLen), byte(ctLen >> 8)}
	var n, werr = conn.TCPConn.Write(ctHeaderBs[:])
	wn += n
	if nil != werr {
		return wn + n, werr
	}

	if 0 < ctLen {
		var wcn, wcerr = conn.TCPConn.Write(contentBs)
		wn += wcn
		if nil != wcerr {
			err = wcerr
		}
		if wcn < len(contentBs) {
			err = io.ErrShortWrite
		}
	}

	return wn, err
}

func buildPreBs() []byte {
	var chsrcPre [6]byte
	copy(chsrcPre[:5], CHSRCType)
	return append(chsrcPre[:5], CHSRCCurVer)
}

func buildSection(num byte, ctBs []byte) *Section {
	var title = titles[num]
	var ctLen = len(ctBs)
	return &Section{
		TitleNum: num,
		Title:    title,
		CtLen:    ctLen,
		Content:  ctBs,
	}
}

// AESCBCCodec aes cbc codec,
// 包含 padding 处理，可以接受任意大于0长度的输入
func AESCBCCodec(key []byte, inBs []byte, encrypt bool) ([]byte, error) {
	var cipherBlock, cipherErr = aes.NewCipher(key[:])
	if nil != cipherErr {
		return nil, cipherErr
	}

	var bSize = aes.BlockSize
	var ctLen = len(inBs)
	var iv = make([]byte, aes.BlockSize)
	var srcBs, dstBs []byte
	var mode cipher.BlockMode
	if encrypt {
		if _, err := io.ReadFull(rand.Reader, iv); nil != err {
			return nil, err
		}
		var padLen = bSize - (ctLen % bSize)
		ctLen = ctLen + padLen
		srcBs = make([]byte, ctLen)
		dstBs = make([]byte, ctLen+16)
		// padding 长度作为值写入 padding 部分
		for i := ctLen - 1; i >= ctLen-padLen; i-- {
			srcBs[i] = byte(padLen)
		}
		mode = cipher.NewCBCEncrypter(cipherBlock, iv)
		copy(srcBs, inBs)
		// iv 写入密文的第一个 block
		copy(dstBs[:bSize], iv)
		mode.CryptBlocks(dstBs[bSize:], srcBs)
	} else {
		// 读取 iv
		iv = inBs[:bSize]
		ctLen = ctLen - bSize
		srcBs = inBs[bSize:]
		dstBs = make([]byte, ctLen)
		mode = cipher.NewCBCDecrypter(cipherBlock, iv)
		mode.CryptBlocks(dstBs, srcBs)
		// 读取 padding 长度
		var padLen = dstBs[ctLen-1]
		dstBs = dstBs[:ctLen-int(padLen)]
	}

	return dstBs, nil
}
