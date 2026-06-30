package main

import (
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
)

// Padding constants
const (
	NoPadding     = 0
	AddPadding    = 1
	RemovePadding = 2
)

var NumFirstPaddings = 8

var bufferPool = sync.Pool{
	New: func() any { b := make([]byte, 64*1024); return &b },
}

func getPooledBuf() (*[]byte, []byte) {
	p := bufferPool.Get().(*[]byte)
	if len(*p) == 0 {
		*p = make([]byte, 32*1024)
	}
	return p, *p
}

func closeWrite(c io.Closer) {
	if c == nil {
		return
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	c.Close()
}

type closeWriter interface {
	CloseWrite() error
}

type timeoutConn struct{ net.Conn }

func (tc *timeoutConn) CloseWrite() error {
	if cw, ok := tc.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func copyConn(dst, src net.Conn) {
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[0:cap(buf)]
	_, _ = io.CopyBuffer(dst, src, buf)
	bufferPool.Put(bufPtr)
}

// dualStream copies bytes from target to clientWriter and from clientReader to target, with optional padding.
func dualStream(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer, padding bool) error {
	stream := func(w io.Writer, r io.Reader, paddingType int) error {
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		buf = buf[0:cap(buf)]
		_, _err := flushingIoCopy(w, r, buf, paddingType) // Pass paddingType
		bufferPool.Put(bufPtr)

		if cw, ok := w.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		return _err
	}
	if padding {
		go stream(target, clientReader, RemovePadding)
		return stream(clientWriter, target, AddPadding)
	}
	go stream(target, clientReader, NoPadding) //nolint: errcheck
	return stream(clientWriter, target, NoPadding)
}

// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.ResponseWriter, it will do a simple io.CopyBuffer().
// Based on forwardproxy implementation.
func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte, paddingType int) (written int64, err error) {
	rw, ok := dst.(http.ResponseWriter)
	var rc *http.ResponseController
	if ok {
		rc = http.NewResponseController(rw)
	}
	var numPadding int
	for {
		var nr int
		var er error
		if paddingType == AddPadding && ((NumFirstPaddings > 0 && numPadding < NumFirstPaddings) || NumFirstPaddings < 0) {
			numPadding++
			paddingSize := rand.Intn(256)
			// Ограничиваем чтение, чтобы всё влезло в 64KB буфер вместе с заголовком и паддингом
			maxRead := len(buf) - 3 - paddingSize
			nr, er = src.Read(buf[3 : 3+maxRead])
			if nr > 0 {
				buf[0] = byte(nr / 256)
				buf[1] = byte(nr % 256)
				buf[2] = byte(paddingSize)
				// Заполняем паддинг случайными байтами вместо нулей
				if paddingSize > 0 {
					rand.Read(buf[3+nr : 3+nr+paddingSize])
				}
				nr += 3 + paddingSize
			}
		} else if paddingType == RemovePadding && ((NumFirstPaddings > 0 && numPadding < NumFirstPaddings) || NumFirstPaddings < 0) {
			numPadding++
			_, er = io.ReadFull(src, buf[0:3])
			if er != nil {
				break
			}
			dataLen := int(buf[0])*256 + int(buf[1])
			paddingSize := int(buf[2])

			// Читаем данные
			nr, er = io.ReadFull(src, buf[0:dataLen])
			if er != nil {
				break
			}

			// Читаем и отбрасываем паддинг
			if paddingSize > 0 {
				var junk [256]byte
				_, er = io.ReadFull(src, junk[0:paddingSize])
				if er != nil {
					break
				}
			}
		} else {
			nr, er = src.Read(buf)
		}
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if rc != nil {
				ef := rc.Flush()
				if ef != nil {
					err = ef
					break
				}
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}
