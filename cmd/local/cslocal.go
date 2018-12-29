package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"time"

	"../../pkg/cmux"
	"../../pkg/cryptostream"
	"../../pkg/kcpconf"
	"../../pkg/xsocks5"

	kcp "github.com/xtaci/kcp-go"
	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

type Options struct {
	local       string
	remote      string
	key         string
	method      string
	authEnabled bool
	mode        string
	socks5      string
}

var (
	option    = Options{local: "127.0.0.1:1080", remote: "", key: "password", method: "aes-128-cfb", authEnabled: false}
	gmux      *cmux.CMUX
	connmutx  sync.Mutex
	reconnect *sync.Cond
)

var (
	PROXY_TCPCONN byte = 0
	PROXY_UDPPACK byte = 1
)

//Create Upstream from multi protocol
func getUPStream() (stream io.ReadWriteCloser, err error) {
	switch option.mode {
	case "tcp":
		var tcpconn net.Conn = nil
		log.Printf("target is : tcp://%s proxy is %s", option.remote, option.socks5)
		if option.socks5 != "" {
			dialer, err2 := proxy.SOCKS5("tcp", option.socks5, nil, proxy.Direct)
			err = err2
			if err != nil {
				return nil, err
			}
			tcpconn, err = dialer.Dial("tcp", option.remote)

		} else {
			tcpconn, err = net.DialTimeout("tcp", option.remote, 3e9)
		}

		if err != nil {
			return nil, err
		}
		return makeCryptoStreamClient(tcpconn)
	case "websocket":

		url := fmt.Sprintf("ws://%s/wshandler", option.remote)
		log.Printf("target is : %s", url)
		ws, err := websocket.Dial(url, "", "/")
		if err != nil {
			return nil, err
		}
		return makeCryptoStreamClient(ws)
	case "http":
		url := fmt.Sprintf("http://%s/directtcp", option.remote)
		log.Printf("target is : %s", url)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		tcpconn, err := net.DialTimeout("tcp", option.remote, 3e9)
		if err != nil {
			return nil, err
		}
		req.Write(tcpconn)
		return makeCryptoStreamClient(tcpconn)
	case "kcp":
		var block kcp.BlockCrypt
		block, _ = kcp.NewAESBlockCrypt([]byte(option.key))
		//conn, _ := kcp.DialWithOptions("65.49.217.54:6868", block, 10, 3)
		conn, _ := kcp.DialWithOptions(option.remote, block, 10, 3)
		if err = conn.SetReadBuffer(5 * 1024 * 1024); err != nil {
			return
		}
		if err = conn.SetWriteBuffer(5 * 1024 * 1024); err != nil {
			return
		}
		conn.SetStreamMode(true)
		cfg := &kcpconf.KCPSessionConfig{WriteDelay: false, MTU: 1400, Win: [2]int{1024, 1024}, ACKNoDelay: true, NoDelay: [4]int{1, 10, 0, 1}}
		conn.SetWriteDelay(cfg.WriteDelay)
		conn.SetNoDelay(cfg.NoDelay[0], cfg.NoDelay[1], cfg.NoDelay[2], cfg.NoDelay[3])
		conn.SetMtu(cfg.MTU)
		conn.SetWindowSize(cfg.Win[0], cfg.Win[1])
		conn.SetACKNoDelay(cfg.ACKNoDelay)
		cfgjson, _ := json.Marshal(cfg)
		log.Printf("send cfg %s %d\n", string(cfgjson), len(cfgjson))
		if err = kcpconf.WriteControlPack(cfgjson, kcpconf.KCP_CMD_SESSION_CFG, conn); err != nil {
			return nil, nil
		}
		return conn, err
	default:
		log.Printf("wrong mode : %s", option.mode)

	}
	return nil, errors.New("wrong mode")
}

//Create encryted stream from iv
func makeCryptoStreamClient(stream io.ReadWriteCloser) (cstream io.ReadWriteCloser, err error) {
	//step2: get iv from remote
	iv := [16]byte{}
	n, err := io.ReadAtLeast(stream, iv[:], 16)
	if err != nil || (n < 16) {
		err = fmt.Errorf("read iv failed")
		return nil, err
	}
	log.Printf("iv recved")
	//step3 create CryptoStream from iv
	cstream, err = cryptostream.NewCryptoStream(stream, option.method, []byte(option.key), iv[:])
	return cstream, err
}

//Dial Proxy server and make Mux over the link
func dialProxy() (mux *cmux.CMUX, err error) {
	err = nil
	mux = nil
	//stackbuf := [512]byte{} //alloc from stack ,do not use make
	//step1 Connect server
	upconn, err := getUPStream()
	if err != nil {
		return nil, err
	}
	//from now on , all data protected by key and iv
	//step 4 do auth
	if option.authEnabled {
		//send auth informations
	} else {
		//send magic
		stackbuf := [16]byte{}
		rand.Read(stackbuf[4:])
		binary.BigEndian.PutUint32(stackbuf[0:4], 0x645812E1)
		upconn.Write(stackbuf[0:16])
	}
	//step 5 create mux
	//Don't use big buffer here, the broken transfer will block the traffic
	mux, err = cmux.NewCMux(upconn, 64*1024) //yamux.Client(conn, muxcfg)
	return mux, err

	if err != nil {
		return nil, err
	}
	//step 6 create control channel
	// controlChannel, err := mux.OpenStream()
	// if err != nil {
	// 	return nil, err
	// }

	return mux, err
}

func upstreamMonitor() {
	defer log.Printf("upstreamMonitor close") //should never happen
	reconnect = sync.NewCond(&connmutx)
	for {
		mux, err := dialProxy()
		log.Printf("Try connect server")
		if err != nil {
			log.Printf("Connect failed... %s\n", err)
			time.Sleep(2e9)
			continue
		} else {
			gmux = mux
			log.Printf(":connected...\n")
			reconnect.L.Lock()
			reconnect.Wait()
			log.Printf("UpLink disconnected\n")
			gmux.Close()
			gmux = nil
			reconnect.L.Unlock()
		}
	}
}

var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 32*1024) },
}

func tcpProxy(in io.ReadWriteCloser, out io.ReadWriteCloser) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	_, err := io.CopyBuffer(in, out, buf)
	if err != nil {
		//fmt.Printf("%s\n", err)
	}
	in.Close()
	out.Close()
}

func getAgent() (io.ReadWriteCloser, error) {
	if gmux == nil {
		return nil, fmt.Errorf("Not Ready")
	}

	start := time.Now()
	agent, err := gmux.OpenStream()
	if err != nil {
		reconnect.Broadcast()
		return nil, err
	}
	elapsed := time.Now().Sub(start)
	if elapsed > 5e8 {
		log.Printf("long create time %d ns\n", elapsed)
	}
	//log.Printf("long gmux.NumStreams() %d\n", gmux.NumStreams())
	return agent, nil
}
func LocalTCPConn(local_conn net.Conn, addr *xsocks5.TAddr, x *xsocks5.Socks5Server) (err error) {
	agent, err := getAgent()
	if err != nil {
		return err
	}
	//Read Dest address
	saddr := []byte(addr.ToString())
	addrlen := len(saddr)
	lenbuf := [3]byte{}
	lenbuf[0] = PROXY_TCPCONN
	binary.BigEndian.PutUint16(lenbuf[1:3], uint16(addrlen))
	//log.Printf("send AddrLen %d", uint16(addrlen))
	if _, err = agent.Write(lenbuf[0:]); err != nil {
		return err
	}
	if _, err = agent.Write(saddr); err != nil {
		return err
	}

	go tcpProxy(local_conn, agent)

	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	io.CopyBuffer(agent, local_conn, buf)
	local_conn.Close()
	agent.Close()

	return nil
}
func bindUDPPort(ip string, port int) (conn *net.UDPConn, err error) {
	bindaddr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(ip),
	}
	conn, err = net.ListenUDP("udp", &bindaddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func LocalUDPConn(local_conn net.Conn, addr *xsocks5.TAddr, x *xsocks5.Socks5Server) (err error) {
	net.ResolveIPAddr("ip", option.local)
	if x.UDPContext != nil {
		relay := x.UDPContext.(*UDPRelay)
		x.ReplyV4(local_conn, 0x00, 0, uint16(relay.Port))
	}
	var buf [16]byte
	local_conn.Read(buf[:])
	return nil
}

type UDPRelay struct {
	udpconn  *net.UDPConn
	IP       net.IP
	Port     int
	Sessions sync.Map
}

func (ur *UDPRelay) getKey(from *net.UDPAddr) string {
	key := make([]byte, 18)
	copy(key[2:], from.IP)
	binary.BigEndian.PutUint16(key[0:2], uint16(from.Port))
	return string(key)

}

func (ur *UDPRelay) proxyUDPAgent(stream io.ReadWriteCloser, udpconn *net.UDPConn, from *net.UDPAddr) {
	defer stream.Close()
	defer ur.Sessions.Delete(ur.getKey(from))
	buf := make([]byte, 65535+20)
	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	lenbuf := [2]byte{}
	for {
		if readed, err := io.ReadAtLeast(stream, lenbuf[:], 2); err != nil || (readed < 2) {
			return
		}
		dlen := binary.BigEndian.Uint16(lenbuf[:])
		if readed, err := io.ReadAtLeast(stream, buf[3:3+dlen], int(dlen)); err != nil || (readed < int(dlen)) {
			return
		}
		_, err := udpconn.WriteTo(buf[0:dlen+3], from)
		if err != nil {
			return
		}
	}

}
func (ur *UDPRelay) DispatchUDP(data []byte, from *net.UDPAddr) {
	dlen := len(data)
	if data[0] != 0 || data[1] != 0 {
		log.Printf("invalid UDP package e1")
		return
	}
	if data[2] != 0 {
		log.Printf("fragment package found,not support there")
		return
	}

	lenmap := map[byte]byte{0x1: 4 + 6, 0x3: data[4] + 6, 0x4: 16 + 6}
	minLen := lenmap[data[3]]

	if dlen < int(minLen) {
		return
	}
	//data format 0x2 size2byte atype addr port data
	data[0] = PROXY_UDPPACK
	binary.BigEndian.PutUint16(data[1:3], uint16(dlen-3))
	stream, ok := ur.Sessions.Load(ur.getKey(from))
	if ok {
		_, err := stream.(io.ReadWriteCloser).Write(data[1:])
		if err != nil {

			ur.Sessions.Delete(ur.getKey(from))
		}
	} else {
		stream, err := gmux.OpenStream()
		if err != nil {
			return //simple drop the package
		}
		go ur.proxyUDPAgent(stream, ur.udpconn, from)
		ur.Sessions.Store(ur.getKey(from), stream)
		stream.Write(data[:])
	}

}
func UDPRelayIoLoop(relay *UDPRelay) {
	buf := make([]byte, 65535)
	for {
		n, fromAddr, err := relay.udpconn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n > 4 {
			relay.DispatchUDP(buf[0:n], fromAddr)
		}
	}

}
func StartUDPRelay(opt Options) (*UDPRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", option.local)
	if err != nil {
		return nil, err
	}
	udpconn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	udprelay := new(UDPRelay)
	udprelay.udpconn = udpconn
	udprelay.IP = addr.IP
	udprelay.Port = addr.Port
	go UDPRelayIoLoop(udprelay)
	return udprelay, nil
}
func main() {
	var pprofEnable bool = false
	flag.StringVar(&option.local, "l", "127.0.0.1:7080", "specify socks5 nic to use.  defaults to 127.0.0.1:7080")
	flag.StringVar(&option.remote, "s", "", "specify remote address eg: 10.0.0.1:2333")
	flag.StringVar(&option.key, "k", "password", "key to use.  defaults to password")
	flag.StringVar(&option.method, "m", "aes-128-cfb", "method to use.  defaults to aes-128-cfb")
	flag.StringVar(&option.mode, "mode", "tcp", "option mode canbe tcp http websocket")
	flag.BoolVar(&pprofEnable, "pprof", false, "pprof for debugging")
	flag.BoolVar(&option.authEnabled, "auth", false, "Enable/disable Auth")
	flag.StringVar(&option.socks5, "socks5", "", "socks url :127.0.0.1:1080")
	flag.Parse()

	envport := os.Getenv("PORT")
	if envport != "" {
		log.Fatal("$PORT must be set")
	}

	if pprofEnable {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	//fmt.Printf("%v", option)
	if option.remote == "" {
		flag.Usage()
		os.Exit(1)
	}
	gmux = nil
	go upstreamMonitor()
	//
	udpRelay, err := StartUDPRelay(option)
	if err != nil {
		log.Println("UDPRelay Start failed", err)
		return
	}
	srv := xsocks5.Socks5Server{TCPHandler: LocalTCPConn, UDPHandler: LocalUDPConn, UDPContext: udpRelay}
	srv.Start(option.local)
}
