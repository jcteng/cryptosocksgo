package xsocks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	socks5Version = uint8(5)
)

type TAddr struct {
	Raw []byte
}

func (a *TAddr) GetPort() uint16 {
	len := len(a.Raw)
	return binary.BigEndian.Uint16(a.Raw[len-2 : len])

}
func (a *TAddr) TAddrFromString(strAddr string) {

}
func (a *TAddr) ToString() string {
	return fmt.Sprintf("%s:%d", a.ToAddrString(), a.GetPort())
}
func (a *TAddr) ToAddrString() string {
	out := ""
	len := len(a.Raw)
	switch a.Raw[1] {
	case 1:
		out = fmt.Sprintf("%d.%d.%d.%d", a.Raw[2], a.Raw[3], a.Raw[4], a.Raw[5])
		break
	case 3:
		out = fmt.Sprintf("%s", a.Raw[2:len-2])
		break
	case 4:
		out = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			a.Raw[2], a.Raw[3], a.Raw[4], a.Raw[5],
			a.Raw[6], a.Raw[7], a.Raw[8], a.Raw[9],
			a.Raw[10], a.Raw[11], a.Raw[12], a.Raw[13],
			a.Raw[14], a.Raw[15], a.Raw[16], a.Raw[17])
		break
	}
	return out
}

type Socks5Profiler struct {
	ConnCreate               int64 // client link created
	ConnClosed               int64 // client link created
	ConnParseFail            int64 // parser failed count
	ConnTCPUpStreamInflight  int64 // on connect	(state)
	ConnTCPUpStreamFailed    int64 // connect failed (total)
	ConnTCPUpStreamActiveIn  int64 // active tcp (state)
	ConnTCPUpStreamActiveOut int64 // active tcp (state)
	ConnTCPUpStreamActive    int64 // active tcp (state)
	ConnUDPActive            int64
	ConnBINDActive           int64
}

const (
	defaultQueueSize = 128
)

type Socks5Server struct {
	TCPHandler    T_TCPHandler
	UDPHandler    T_UDPHandler
	UDPContext    interface{}
	BINDHandler   T_BINDHandler
	NoFakeAck     bool //return a dummy address to socks5 client
	DummyReplayV4 []byte
	ConnTimeout   time.Duration
	profile       Socks5Profiler
}

type T_TCPHandler func(net.Conn, *TAddr, *Socks5Server) error
type T_UDPHandler func(net.Conn, *TAddr, *Socks5Server) error
type T_BINDHandler func(net.Conn, *TAddr, *Socks5Server) error

type netConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}

func pipeConns(wg *sync.WaitGroup, in netConn, out netConn, profiler *int64, x *Socks5Server) {

	io.Copy(in, out)
	atomic.AddInt64(profiler, -1)
	in.Close() //Close other side
	out.Close()
	wg.Done()
}

func LocalTCPConn(local_conn net.Conn, addr *TAddr, x *Socks5Server) error {
	atomic.AddInt64(&x.profile.ConnTCPUpStreamInflight, 1)
	atomic.AddInt64(&x.profile.ConnTCPUpStreamActive, 1)

	defer atomic.AddInt64(&x.profile.ConnTCPUpStreamActive, -1)
	agent_conn, err := net.DialTimeout("tcp", addr.ToString(), x.ConnTimeout)
	atomic.AddInt64(&x.profile.ConnTCPUpStreamInflight, -1)

	if err != nil {
		atomic.AddInt64(&x.profile.ConnTCPUpStreamFailed, 1)
		agent_conn.Close()
		return err
	}
	atomic.AddInt64(&x.profile.ConnTCPUpStreamActiveIn, 1)
	atomic.AddInt64(&x.profile.ConnTCPUpStreamActiveOut, 1)

	var wg = new(sync.WaitGroup)
	wg.Add(2)
	//memory cost 2*32KB memory each connection pair
	go pipeConns(wg, local_conn, agent_conn, &x.profile.ConnTCPUpStreamActiveIn, x)
	go pipeConns(wg, agent_conn, local_conn, &x.profile.ConnTCPUpStreamActiveOut, x)
	wg.Wait()

	return nil
}
func (x *Socks5Server) handleRequest(conn net.Conn, cmd byte, addr *TAddr) error {
	var err error
	err = nil

	switch cmd {
	case 0x1:
		if x.TCPHandler == nil {
			err = LocalTCPConn(conn, addr, x)
		} else {
			err = x.TCPHandler(conn, addr, x)
		}
		break
	case 0x3:
		if x.UDPHandler == nil {
			err = x.ReplyV4(conn, 0x7, 0, 0)
		} else {
			err = x.UDPHandler(conn, addr, x)
		}
		break
	case 0x4:
		if x.BINDHandler == nil {
			err = x.ReplyV4(conn, 0x7, 0, 0)
		} else {
			err = x.BINDHandler(conn, addr, x)
		}
		break
	}

	return err
}

func (x *Socks5Server) processSocks5(conn net.Conn) (error, byte, *TAddr) {
	stackbuf := [512]byte{} //alloc from stack ,do not use make

	//set timeout of the Read
	conn.SetDeadline(time.Now().Add(time.Duration(3e9)))

	defer conn.SetDeadline(time.Time{})
	// Read the version byte
	verbuf := stackbuf[0:3]

	len, err := io.ReadAtLeast(conn, verbuf, 3)
	//fmt.Printf("%x %x %x\n", verbuf[0], verbuf[1], verbuf[2])
	if err != nil {
		return err, 0, nil
	}
	if verbuf[0] != 0x5 || verbuf[1] != 0x1 || verbuf[2] != 0x0 { //5 1 0
		fmt.Printf("auth method not support\n")
	}

	len, err = conn.Write([]byte{5, 0})
	if err != nil || len < 2 {
		return err, 0, nil
	}
	requestbuf := stackbuf[0:5]
	len, err = io.ReadAtLeast(conn, requestbuf, 5)
	if err != nil || len < 5 {
		return err, 0, nil
	}
	atypeSizeMap := map[byte]byte{0x1: 4 + 2 - 1, 0x3: requestbuf[4] + 2, 0x4: 16 + 2 - 1}
	cmd := requestbuf[1]
	atype := requestbuf[3]
	if !((atype == 0x1) || (atype == 0x3) || (atype == 0x4)) {
		return fmt.Errorf("Not supprted Atype %d", atype), 0, nil
	}
	size_to_read := atypeSizeMap[atype]
	//convert to type/size/addr
	var addrbuf []byte
	if atype == 0x3 {
		addrbuf = stackbuf[0 : size_to_read+2]
		len, err = io.ReadAtLeast(conn, addrbuf[2:], int(size_to_read))
		if err != nil || len < int(size_to_read) {
			return err, 0, nil
		}
		size_to_read += 1

	} else {
		addrbuf = stackbuf[0 : size_to_read+3]
		addrbuf[2] = requestbuf[4]
		len, err = io.ReadAtLeast(conn, addrbuf[3:], int(size_to_read))
		if err != nil || len < int(size_to_read) {
			return err, 0, nil
		}
	}
	addrbuf[1] = atype
	addrbuf[0] = size_to_read

	addr := new(TAddr)
	addr.Raw = addrbuf
	//fmt.Printf("cmd %d addr %s\n", cmd, addr.ToString())
	//fake a address to client
	if !x.NoFakeAck && cmd == 0x1 {

		conn.Write(x.DummyReplayV4)
	}
	return err, cmd, addr
}

func (x *Socks5Server) ReplyV4(conn net.Conn, response byte, addr uint32, port uint16) error {
	//_, err := conn.Write([]byte{5, 0, 0, 1, 12, 12, 12, 12, (port >> 8), port & 8)})
	_, err := conn.Write([]byte{5, response, 0, 1, byte(addr >> 24), byte(addr >> 16), byte(addr >> 8), byte(addr), byte(port >> 8), byte(port)})
	return err
}
func (x *Socks5Server) OnSocks5Conn(conn net.Conn) error {
	atomic.AddInt64(&x.profile.ConnCreate, 1)

	defer func() { atomic.AddInt64(&x.profile.ConnClosed, 1) }()
	err, cmd, addr := x.processSocks5(conn)
	if err != nil {
		conn.Close()
		//no reply to client ,simple close it
		atomic.AddInt64(&x.profile.ConnParseFail, 1)
		return err
	}
	err = x.handleRequest(conn, cmd, addr)
	return err
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func (x *Socks5Server) StartDefault() {
	x.Start("127.0.0.1:1080")
}

func humanReadable(value uint64) string {
	if value > 1024*1024*1024*1024 {
		return fmt.Sprintf(`%f TB`, float64(value)/float64(1024*1024*1024*1024))
	}
	if value > 1024*1024*1024 {
		return fmt.Sprintf(`%f GB`, float64(value)/float64(1024*1024*1024))
	}
	if value > 1024*1024 {
		return fmt.Sprintf(`%f MB`, float64(value)/float64(1024*1024))
	}
	if value > 1024 {
		return fmt.Sprintf(`%f KB`, float64(value)/float64(1024))
	}
	return fmt.Sprintf(`%d Bytes`, value)

}
func profileTimer(x *Socks5Server) {
	timer1 := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-timer1.C:
			{
				fmt.Printf("%v \n", x.profile)
				continue
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				runtime.GC()

				fmt.Printf("Alloc %s TA %s SYS %s GC %d\n", humanReadable(m.Alloc), humanReadable(m.TotalAlloc), humanReadable(m.Sys), m.NumGC)
				fmt.Printf("Lookup %s Malloc %s Free %s \n", humanReadable(m.Lookups), humanReadable(m.Mallocs), humanReadable(m.Frees))
				fmt.Printf("HeapAlloc %s HeapSys %s HeapIdle %s HeapInuse %s HeapReleased %s HeapObjects %s\n",
					humanReadable(m.HeapAlloc), humanReadable(m.HeapSys), humanReadable(m.HeapIdle),
					humanReadable(m.HeapInuse), humanReadable(m.HeapReleased), humanReadable(m.HeapObjects))
				fmt.Printf("Stack %s MSpan %s MCache %s BuckHashSys %s\n", humanReadable(m.StackSys), humanReadable(m.MSpanSys), humanReadable(m.MCacheSys), humanReadable(m.BuckHashSys))

			}

		}
	}
}
func (x *Socks5Server) Start(bindAddr string) {
	//init a default dummy Reply

	if x.DummyReplayV4 == nil {
		x.DummyReplayV4 = []byte{5, 0, 0, 1, 127, 0, 0, 1, 151, 235}
	}
	if x.ConnTimeout == 0 {
		x.ConnTimeout = 15 * 1e9
	}

	//fmt.Printf("%+v\n", x)
	l, err := net.Listen("tcp", bindAddr)

	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	//go profileTimer(x)
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on " + bindAddr)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go x.OnSocks5Conn(conn)
	}
}

//sample to use this
//xsrv := xsocks5.Socks5Server{}
//go xsrv.Start("127.0.0.1:7080")
