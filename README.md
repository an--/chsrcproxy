# README

## chsrc_proxy 

自定义的 TCP 上的转发代理传输协议

*   兼容 socks5 协议, 作为本地代理入口
*   对传输内容进行 AES 加密
*   使用 rsa 交换 AES 密钥
*   使用本地 CA 证书对对方的证书进行验证