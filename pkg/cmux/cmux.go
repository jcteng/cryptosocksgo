package cmux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
)

var ()

type CChannel struct {
	cmux      *CMUX
	writeTo   io.Writer
	id        uint32
	_eofmux   sync.Mutex
	eofCond   *sync.Cond
	buf       [][]byte
	rmux      sync.Mutex
	readCond  *sync.Cond
	write2num int64
	state     int
}
type CMUX struct {
	conn               io.ReadWriter
	newChannels        []*CChannel
	liveChannels       sync.Map //map[uint32]*CChannel
	_acceptmux         sync.Mutex
	accpetCond         *sync.Cond
	channelIndex       uint32
	connWmutx          sync.Mutex
	blockLenMax        int
	state              int
	totalChannel       int
	totalChannelClosed int
}

func (cmux *CMUX) Close() (err error) {

	return nil
}
func closeAllChannel(key, value interface{}) bool {
	value.(*CChannel).doClose()
	return true
}
func (cmux *CMUX) onError() (err error) {
	cmux.liveChannels.Range(closeAllChannel)
	cmux.accpetCond.Broadcast()
	cmux.state = 0x1

	return nil
}

var (
	CHANNEL_NEW   byte = 0
	CHANNEL_DATA  byte = 1
	CHANNEL_CLOSE byte = 2
)

func readLoopMux(cmux *CMUX) {
	var recvBuf = make([]byte, cmux.blockLenMax)
	recvAfterClose := 0
	for {
		//log.Printf("Wait for Next")
		if n, err := io.ReadAtLeast(cmux.conn, recvBuf[0:9], 9); (n < 9) || (err != nil) {
			//log.Printf("Error on Read")
			cmux.onError()
			return
		}

		cmd := recvBuf[0]
		len := binary.BigEndian.Uint32(recvBuf[1:5])
		cid := binary.BigEndian.Uint32(recvBuf[5:9])

		switch cmd {
		case CHANNEL_NEW: //new channel
			channel, _ := NewCChannel(cmux, cid) //new(CChannel)
			cmux.accpetCond.L.Lock()
			cmux.newChannels = append(cmux.newChannels, channel)
			cmux.liveChannels.Store(channel.id, channel)
			//log.Printf("New Channel[%d]", channel.id)
			cmux.accpetCond.Signal()
			cmux.accpetCond.L.Unlock()
			break
		case CHANNEL_DATA: // channel data
			//log.Printf("Channel Data %d %d %d", cmd, len, cid)
			readed, err := io.ReadAtLeast(cmux.conn, recvBuf[0:len], int(len))
			if readed < int(len) {
				log.Printf("recv shot readed")
				cmux.onError()
				return
			}
			if err != nil {
				log.Printf("On Read Error")
				cmux.onError()
				return
			}

			channel, ok := cmux.liveChannels.Load(cid)
			if ok {
				channel.(*CChannel).onRecv(recvBuf[0:len])
			} else {
				recvAfterClose++
				//log.Printf("Channel[%d]%d Recv after close", cid, recvAfterClose)
			}

			break
		case CHANNEL_CLOSE: //close channel
			channel, ok := cmux.liveChannels.Load(cid)
			if ok {
				channel.(*CChannel).doClose()
			}
			break
		}

	}
}
func NewCMux(conn io.ReadWriter, blocklen int) (cmux *CMUX, err error) {
	cmux = new(CMUX)
	cmux.conn = conn
	cmux.channelIndex = 1
	cmux.blockLenMax = blocklen
	cmux.accpetCond = sync.NewCond(&cmux._acceptmux)
	go readLoopMux(cmux)
	return cmux, nil
}

func (cmux *CMUX) AcceptStream() (channel *CChannel, err error) {
	return cmux.Accept()
}
func (cmux *CMUX) Accept() (channel *CChannel, err error) {

	cmux.accpetCond.L.Lock()
	count := len(cmux.newChannels)
	if count == 0 {
		cmux.accpetCond.Wait()
		if cmux.state == 0x01 {
			return nil, fmt.Errorf("Mux on Error")
		}
	}
	channel = cmux.newChannels[0]
	cmux.newChannels = cmux.newChannels[1:]
	cmux.accpetCond.L.Unlock()
	return channel, nil
}

//always create by client
func (cmux *CMUX) OpenStream() (channel *CChannel, err error) {
	if cmux.state == 0x01 {
		return nil, fmt.Errorf("Mux on Error")
	}
	var stackBuf [16]byte
	channel, _ = NewCChannel(cmux, cmux.channelIndex)
	cmux.channelIndex++
	stackBuf[0] = CHANNEL_NEW
	binary.BigEndian.PutUint32(stackBuf[1:5], 0)
	binary.BigEndian.PutUint32(stackBuf[5:9], channel.id)
	cmux.connWmutx.Lock()
	cmux.conn.Write(stackBuf[0:9])
	cmux.connWmutx.Unlock()
	cmux.liveChannels.Store(channel.id, channel)
	return channel, nil
}

func (channel *CChannel) onRecv(p []byte) (n int, err error) {
	channel.eofCond.L.Lock()
	defer channel.eofCond.L.Unlock()
	if channel.writeTo != nil {
		channel.write2num += int64(len(p))
		n, err = channel.writeTo.Write(p)
	} else {
		cpyBuf := make([]byte, len(p))
		copy(cpyBuf, p)
		channel.readCond.L.Lock()
		channel.buf = append(channel.buf, cpyBuf)
		channel.readCond.Signal()
		channel.readCond.L.Unlock()
	}
	return
}

func (channel *CChannel) WriteTo(w io.Writer) (n int64, err error) {

	channel.eofCond.L.Lock()
	channel.writeTo = w
	channel.write2num = 0
	for i := 0; i < len(channel.buf); i++ {
		w.Write(channel.buf[i])
	}
	channel.buf = nil
	channel.eofCond.Wait()
	channel.eofCond.L.Unlock()
	return channel.write2num, nil
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}
func (channel *CChannel) Read(p []byte) (readed_n int, err error) {
	readed_n = 0
	channel.readCond.L.Lock()
	defer channel.readCond.L.Unlock()
	if len(channel.buf) == 0 {
		channel.readCond.Wait()
		if channel.state == 0x1 {
			return 0, io.EOF
		}
	}
	rlen := len(p)
	blen := len(channel.buf[0])
	readed_n = min(blen, rlen)

	copy(p, channel.buf[0][0:readed_n])
	if blen == readed_n {
		channel.buf = channel.buf[1:]
	} else {
		channel.buf[0] = channel.buf[0][readed_n:]
	}
	return readed_n, nil
}
func (channel *CChannel) Write(wdata []byte) (writen_n int, err error) {
	var stackBuf [16]byte
	stackBuf[0] = CHANNEL_DATA
	wlen := len(wdata)

	writen_n = 0
	for {
		size2write := min(wlen-writen_n, channel.cmux.blockLenMax)

		binary.BigEndian.PutUint32(stackBuf[1:5], uint32(size2write))
		binary.BigEndian.PutUint32(stackBuf[5:9], channel.id)
		if channel.state == 0x1 {
			return writen_n, errors.New("ChannelClosed")
		}
		channel.cmux.connWmutx.Lock()
		if _, err = channel.cmux.conn.Write(stackBuf[0:9]); err != nil {
			channel.cmux.onError()
			return
		}
		if size2write, err = channel.cmux.conn.Write(wdata[writen_n : writen_n+size2write]); err != nil {
			writen_n += size2write
			channel.cmux.onError()
			return
		}
		channel.cmux.connWmutx.Unlock()
		writen_n += size2write
		if writen_n == wlen {
			return
		}
	}
}

func NewCChannel(cmux *CMUX, id uint32) (channel *CChannel, err error) {
	channel = new(CChannel)
	channel.id = id
	channel.cmux = cmux
	channel.eofCond = sync.NewCond(&channel._eofmux)
	channel.readCond = sync.NewCond(&channel.rmux)
	return channel, nil
}

func (channel *CChannel) doClose() (err error) {

	if channel.state != 0x1 {
		channel.state = 0x01         //will raise error on Write Interface
		channel.eofCond.Broadcast()  //raise error on writeTO interface
		channel.readCond.Broadcast() //raise error on Read interface
		channel.cmux.liveChannels.Delete(channel.id)
	}

	return nil
}
func (channel *CChannel) Close() (err error) {
	cmux := channel.cmux
	var stackBuf [16]byte
	stackBuf[0] = CHANNEL_CLOSE
	binary.BigEndian.PutUint32(stackBuf[1:5], 0)
	binary.BigEndian.PutUint32(stackBuf[5:9], channel.id)
	cmux.connWmutx.Lock()
	cmux.conn.Write(stackBuf[0:9])
	cmux.connWmutx.Unlock()
	channel.doClose()
	return nil
}
