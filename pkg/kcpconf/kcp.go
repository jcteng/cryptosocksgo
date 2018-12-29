package kcpconf

import (
	"encoding/binary"
	"fmt"
	"io"
)

type KCPSessionConfig struct {
	WriteDelay bool
	NoDelay    [4]int
	MTU        int
	Win        [2]int
	ACKNoDelay bool
}

const (
	KCP_CMD_RAMDOM_IV    = 0x0
	KCP_CMD_SESSION_CFG  = 0x1
	KCP_CMD_SESSION_AUTH = 0x2
	KCP_CMD_TESTPACK     = 0x3 //send n*1024 testpack to client
)

func ReadControlPack(buf []byte, stream io.ReadWriter) (size uint16, cmd uint16, err error) {
	size = 0
	cmd = 0
	err = nil
	if _, err = io.ReadAtLeast(stream, buf[0:2], 2); err != nil {
		return
	}
	size = binary.BigEndian.Uint16(buf[0:2])
	if size < 2 {
		//not a control channel
		return
	}
	if _, err = io.ReadAtLeast(stream, buf[0:2], 2); err != nil {
		return
	}
	cmd = binary.BigEndian.Uint16(buf[0:2])

	readed, err := io.ReadAtLeast(stream, buf[0:size], int(size))
	if err != nil {
		return
	}
	fmt.Printf("readed %d %d", readed, size)
	return
}
func WriteControlPack(buf []byte, cmd uint16, stream io.ReadWriter) (err error) {
	wbuf := [4]byte{}
	err = nil

	binary.BigEndian.PutUint16(wbuf[0:2], uint16(len(buf)))
	binary.BigEndian.PutUint16(wbuf[2:4], cmd)
	if _, err = stream.Write(wbuf[0:4]); err != nil {
		return err
	}
	_, err = stream.Write(buf)
	return
}
