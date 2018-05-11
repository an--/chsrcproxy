package protocol

// 协议相关常量
const (
	TCPType = "tcp" // tcp 协议

	SOCKS5Type    = "socks5"
	SOCKS5Ver     = 5
	SOCKS5CmdConn = 1
	SOCKS5RSV     = 0

	SOCKS5RepSuc        = 0
	SOCKS5Repfail       = 1
	SOCKS5RepCmdNotsup  = 7
	SOCKS5RepAddrNotSup = 8

	CHSRCType    = "chsrc"
	CHSRCDefPort = 1270    // 默认端口
	CHSRCCurVer  = byte(1) // 当前版本
)
