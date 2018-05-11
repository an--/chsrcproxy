package protocol

import (
	"io"
	"net"
)

// TCPChsrcChannel tcp 到 chsrc 的管道
type TCPChsrcChannel struct {
	TCPConn   *net.Conn
	ChsrcConn *ChsrcConn

	tcpwn   int64
	chsrcwn int64
}

func (ch *TCPChsrcChannel) Trans() error {
	var tcErrCh = make(chan error)
	var ctErrCh = make(chan error)
	go ch.tcp2ChsrcChan(tcErrCh)
	go ch.chsrc2TCPChan(ctErrCh)

	var tcErr = <-tcErrCh
	var ctErr = <-ctErrCh

	if nil != tcErr {
		return tcErr
	}
	if nil != ctErr {
		return ctErr
	}
	return nil
}

func (ch *TCPChsrcChannel) tcp2ChsrcChan(errChan chan error) {
	var err = ch.tcp2Chsrc()
	errChan <- err
}

func (ch *TCPChsrcChannel) tcp2Chsrc() (err error) {
	var size = 8 * 1024
	var buf = make([]byte, size)

	for {
		var rn, rerr = (*ch.TCPConn).Read(buf)
		if 0 < rn {
			// chsrc 写入时，包含 section head 信息，要多 3 字节
			var wn, werr = ch.ChsrcConn.WriteData(buf[:rn])
			if 0 < wn {
				ch.chsrcwn += int64(wn)
			}
			if nil != werr {
				err = werr
				break
			}
			if wn-3 < rn {
				err = io.ErrShortWrite
				break
			}
		}

		if nil != rerr {
			if io.EOF != rerr {
				err = rerr
			}
			break
		}
	}
	return err
}

func (ch *TCPChsrcChannel) chsrc2TCPChan(errChan chan error) {
	var err = ch.chsrc2TCP()
	errChan <- err
}

func (ch *TCPChsrcChannel) chsrc2TCP() (err error) {
	for {
		var data, rerr = ch.ChsrcConn.ReadData()
		if nil != data && 0 < len(data) {
			var rn = len(data)
			var wn, werr = (*ch.TCPConn).Write(data)
			ch.tcpwn += int64(wn)
			if nil != werr {
				err = werr
				break
			}
			if wn < rn {
				err = io.ErrShortWrite
				break
			}
		}
		if nil != rerr {
			if io.EOF != rerr {
				err = rerr
			}
			break
		}
	}
	return err
}

type ChsrcChannel struct {
	SrcConn *ChsrcConn
	DstConn *ChsrcConn

	toSrcWn int64
	toDstWn int64
}

func (ch *ChsrcChannel) Trans() error {
	var toSrcErrCh chan error
	var toDstErrCh chan error
	var toSrcWnCh chan int64
	var toDstWnCh chan int64

	go ch.src2Dst(toSrcErrCh, toSrcWnCh)
	go ch.dst2Src(toDstErrCh, toDstWnCh)

	var toSrcErr = <-toSrcErrCh
	var toDstErr = <-toDstErrCh
	ch.toSrcWn = <-toSrcWnCh
	ch.toDstWn = <-toDstWnCh

	if nil != toSrcErr {
		return toSrcErr
	}
	if nil != toDstErr {
		return toDstErr
	}
	return nil
}

func (ch *ChsrcChannel) src2Dst(errCh chan error, wnCh chan int64) {
	var wn, err = copyChsrc(ch.SrcConn, ch.DstConn)
	errCh <- err
	wnCh <- wn
}

func (ch *ChsrcChannel) dst2Src(errCh chan error, wnCh chan int64) {
	var wn, err = copyChsrc(ch.DstConn, ch.SrcConn)
	errCh <- err
	wnCh <- wn
}

func copyChsrc(srcConn, dstConn *ChsrcConn) (wn int64, err error) {
	for {
		var data, rerr = srcConn.ReadData()
		if nil != data && 0 < len(data) {
			var rn = len(data)
			var dwn, werr = dstConn.WriteData(data)
			wn += int64(dwn)
			if nil != werr {
				err = werr
				break
			}
			if dwn-3 < rn {
				err = io.ErrShortWrite
				break
			}
		}
		if nil != rerr {
			if io.EOF != rerr {
				err = rerr
			}
			break
		}
	}
	return 0, err
}
