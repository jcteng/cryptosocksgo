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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jcteng/cryptosocksgo/pkg/cmux"
	"github.com/jcteng/cryptosocksgo/pkg/cryptostream"
	"github.com/jcteng/cryptosocksgo/pkg/kcpconf"
	kcp "github.com/xtaci/kcp-go"
	"golang.org/x/net/websocket"
)

type Options struct {
	bind     string
	port     int
	httpport int
	key      string
	method   string
	mode     string
}

var (
	option = Options{bind: "0.0.0.0", port: 666, key: "password", method: "aes-128-cfb"}
)

func tcpProxy(in io.ReadWriteCloser, out io.ReadWriteCloser) {
	_, err := io.Copy(in, out)
	if err != nil {
		//fmt.Printf("%s\n", err)
	}
	in.Close()
	out.Close()
}
func proxyTCPConn(stream io.ReadWriteCloser) {
	defer stream.Close()
	stackbuf := [512]byte{} //alloc from stack ,do not use make
	var err error = nil
	buf := stackbuf[0:]
	readed := 0

	if readed, err = io.ReadAtLeast(stream, buf[0:2], 2); err != nil || (readed < 2) {
		log.Printf("shot read %d", readed)
		return
	}
	addrlen := binary.BigEndian.Uint16(buf[0:2])
	//log.Printf("addrlen %d", addrlen)
	if readed, err = io.ReadAtLeast(stream, buf[0:addrlen], int(addrlen)); err != nil || (readed < int(addrlen)) {
		log.Printf("shot read %d", readed)
		return
	}
	addrstr := string(buf[0:addrlen])
	log.Println("new TCP Connection:", addrstr)
	agentconn, err := net.DialTimeout("tcp", addrstr, 3e9)
	if err != nil {
		return
	}
	defer agentconn.Close()
	agentconn.(*net.TCPConn).SetNoDelay(true)
	agentconn.(*net.TCPConn).SetReadBuffer(4 * 1024 * 1024)
	agentconn.(*net.TCPConn).SetWriteBuffer(4 * 1024 * 1024)

	go tcpProxy(stream, agentconn)
	io.Copy(agentconn, stream)

}

func makeCryptoStream(stream io.ReadWriteCloser) (cstream io.ReadWriteCloser, err error) {
	//Step 1: provide the iv to client
	iv := [16]byte{}
	rand.Read(iv[:])
	stream.Write(iv[0:16])
	fmt.Printf("Write IV \n")
	//Step2 create CryptoStream over tcp conn
	cstream, err = cryptostream.NewCryptoStream(stream, option.method, []byte(option.key), iv[:])
	if err != nil {
		return nil, err
	}

	return cstream, nil
}
func onClientConn(tcpconn io.ReadWriteCloser) (err error) {
	var mux *cmux.CMUX
	defer tcpconn.Close()
	//Step4 if auth required , do it
	authEnabled := false
	if authEnabled {
		stackbuf := [512]byte{} //alloc from stack ,do not use make
		buf := stackbuf[0:]
		//Auth
		kcpconf.ReadControlPack(buf, tcpconn)
		//verify autinfo
		//
	} else {
		stackbuf := [16]byte{}
		if n, err := io.ReadAtLeast(tcpconn, stackbuf[:], 16); n < 16 || err != nil {

			return errors.New("Magic check fail")
		}
		if 0x645812E1 != binary.BigEndian.Uint32(stackbuf[0:4]) {
			return errors.New("Magic check fail")
		}
	}

	mux, err = cmux.NewCMux(tcpconn, 64*1024) //yamux.Server(conn, muxcfg)

	if err != nil {
		return
	}

	//Step5 create control channel over mux
	// controlChannel, err := mux.AcceptStream()
	// if err != nil {
	// 	return
	// }
	// log.Println("Control Channel Connected:", tcpconn.RemoteAddr())

	//Step6 do proxy connections
	stackbuf := [16]byte{}
	for {
		muxconn, err := mux.AcceptStream()
		if err != nil {
			return nil
		}
		if readed, err := io.ReadAtLeast(muxconn, stackbuf[0:1], 1); err != nil || (readed < 1) {

			return err
		}
		switch stackbuf[0] {
		case 0:
			go proxyTCPConn(muxconn)
			break
		case 1:
			go proxyUDPPACK(muxconn)
			break
		}

	}
}

var UDPRECV_OFFSET = 30

func proxyUDPAgent(stream io.ReadWriteCloser, udpconn *net.UDPConn) {
	defer stream.Close()
	defer udpconn.Close()
	wbuf := make([]byte, 65535+UDPRECV_OFFSET)
	for {
		udpconn.SetReadDeadline(time.Now().Add(9e11)) //15min timetout
		n, fromAddr, err := udpconn.ReadFromUDP(wbuf[UDPRECV_OFFSET:])
		if err != nil {
			return
		}
		//format size atype addr port data
		v4ip := fromAddr.IP.To4()
		var ipInByte []byte
		if nil != v4ip {
			ipInByte = []byte(v4ip)
		} else {
			ipInByte = []byte(fromAddr.IP)
		}
		iplen := len(ipInByte) //
		atype := byte(0x1)
		if iplen == 16 {
			atype = 0x4
		}
		startPos := UDPRECV_OFFSET - iplen - 5
		binary.BigEndian.PutUint16(wbuf[startPos:startPos+2], uint16(iplen+3+n)) //atype+ip+port+data=1+m+2+
		wbuf[startPos+2] = atype
		copy(wbuf[startPos+3:], ipInByte)
		binary.BigEndian.PutUint16(wbuf[startPos+3+iplen:], uint16(fromAddr.Port))
		_, err = stream.Write(wbuf[startPos : startPos+iplen+3+n+2])
		if err != nil {
			return
		}
	}

}
func proxyUDPPACK(stream io.ReadWriteCloser) {
	defer stream.Close()
	bindaddr := net.UDPAddr{
		Port: 0,
		IP:   net.ParseIP("0.0.0.0"),
	}

	udpconn, err := net.ListenUDP("udp", &bindaddr)
	if err != nil {
		return
	}

	defer udpconn.Close()
	go proxyUDPAgent(stream, udpconn)
	buf := make([]byte, 65535)
	for {
		udpconn.SetReadDeadline(time.Now().Add(9e11)) //15min timetout
		if readed, err := io.ReadAtLeast(stream, buf[0:2], 2); err != nil || (readed < 2) {
			return
		}
		dlen := binary.BigEndian.Uint16(buf[0:2])
		if readed, err := io.ReadAtLeast(stream, buf[0:dlen], int(dlen)); err != nil || (readed < int(dlen)) {
			return
		}
		pack := buf[0:int(dlen)]
		var ip []byte
		var packdata []byte
		var port uint16 = 0
		switch pack[0] {
		case 1:
			ip = pack[1 : 1+4]
			port = binary.BigEndian.Uint16(pack[1+4 : 1+4+2])
			packdata = pack[1+4+2:]
			break
		case 3:
			addrlen := pack[1]
			udpIp, err := net.ResolveUDPAddr("udp", string(pack[2:2+addrlen]))
			if err != nil {
				continue
			}
			ip = udpIp.IP
			port = binary.BigEndian.Uint16(pack[2+addrlen : 2+2+addrlen])
			packdata = pack[2+2+addrlen:]
			break
		case 4:
			ip = pack[1 : 1+16]
			port = binary.BigEndian.Uint16(pack[1+16 : 1+16+2])
			packdata = pack[1+16+2:]
			break
		}
		targetAddr := net.UDPAddr{
			Port: int(port),
			IP:   ip,
		}

		//log.Printf("redirect %v %s:%d", packdata, targetAddr.IP.String(), targetAddr.Port)
		_, err = udpconn.WriteTo(packdata, &targetAddr)
		if err != nil {
			return
		}
	}

}

var (
	DataShard   = 10
	ParityShard = 3
)

func servAsKCP(bindAddr string) {

	var block kcp.BlockCrypt
	block, _ = kcp.NewAESBlockCrypt([]byte(option.key))
	lis, _ := kcp.ListenWithOptions(bindAddr, block, DataShard, ParityShard)
	fmt.Printf("server on kcp://%s\n", bindAddr)
	if err := lis.SetDSCP(46); err != nil {
		return
	}
	if err := lis.SetReadBuffer(5 * 1024 * 1024); err != nil {
		return
	}
	if err := lis.SetWriteBuffer(5 * 1024 * 1024); err != nil {
		return
	}
	stackbuf := [512]byte{} //alloc from stack ,do not use make
	buf := stackbuf[0:]
	for {
		if conn, err := lis.AcceptKCP(); err == nil {
			log.Printf("Client Over KCP")
			conn.SetStreamMode(true)
			{
				cfg := &kcpconf.KCPSessionConfig{WriteDelay: false, MTU: 1400, Win: [2]int{1024, 1024}, ACKNoDelay: true, NoDelay: [4]int{1, 10, 0, 1}}
				conn.SetWriteDelay(cfg.WriteDelay)
				conn.SetNoDelay(cfg.NoDelay[0], cfg.NoDelay[1], cfg.NoDelay[2], cfg.NoDelay[3])
				conn.SetMtu(cfg.MTU)
				conn.SetWindowSize(cfg.Win[0], cfg.Win[1])
				conn.SetACKNoDelay(cfg.ACKNoDelay)
			}
			size, cmd, _ := kcpconf.ReadControlPack(buf, conn)

			if cmd == kcpconf.KCP_CMD_SESSION_CFG {
				cfg := &kcpconf.KCPSessionConfig{}
				err = json.Unmarshal(buf[0:size], cfg)
				if err != nil {
					return
				}
				conn.SetWriteDelay(cfg.WriteDelay)
				conn.SetNoDelay(cfg.NoDelay[0], cfg.NoDelay[1], cfg.NoDelay[2], cfg.NoDelay[3])
				conn.SetMtu(cfg.MTU)
				conn.SetWindowSize(cfg.Win[0], cfg.Win[1])
				conn.SetACKNoDelay(cfg.ACKNoDelay)
			}

			go onClientConn(conn)
		} else {
			log.Printf("%+v", err)
		}
	}
}
func onWSConnected(ws *websocket.Conn) {
	log.Printf("Client Over websocket")
	defer ws.Close()
	cstream, err := makeCryptoStream(ws)
	if err != nil {
		return
	}
	onClientConn(cstream)
}
func servAsTCP(bindAddr string) {

	l, err := net.Listen("tcp", bindAddr)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(2)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on tcp://" + bindAddr)

	for {
		if conn, err := l.Accept(); err == nil {
			log.Printf("Client Over TCP")
			conn.(*net.TCPConn).SetNoDelay(true)
			cstream, err := makeCryptoStream(conn)
			if err != nil {
				conn.Close()
				return
			}
			go onClientConn(cstream)
		} else {
			log.Printf("%+v", err)
		}
	}
}

var testbuf = make([]byte, 65535)

func SpeedTesthandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("SpeedTest")

	for {
		_, err := w.Write(testbuf)
		if err != nil {
			return
		}
		log.Printf(".")
	}
}
func FakePagehandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Client Over Http")
	tcpconn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	cstream, err := makeCryptoStream(tcpconn)
	if err != nil {
		tcpconn.Close()
		return
	}
	onClientConn(cstream)
}
func servAsHttp(bindAddr string) {
	http.HandleFunc("/directtcp", FakePagehandler)
	http.HandleFunc("/speedtest", SpeedTesthandler)
	http.Handle("/wshandler", websocket.Handler(onWSConnected))
	fmt.Println("Listening on http://" + bindAddr)
	log.Fatal(http.ListenAndServe(bindAddr, nil))
}
func main() {
	flag.StringVar(&option.bind, "b", "0.0.0.0", "specify nic to use.  defaults to all")
	flag.IntVar(&option.port, "t", 2333, "specify port to use.  defaults to 2333.")
	flag.IntVar(&option.httpport, "h", 2334, "specify http port to use.  defaults to 2334.")
	flag.StringVar(&option.key, "k", "password", "key to use.  defaults to password")
	flag.StringVar(&option.method, "m", "aes-128-cfb", "method to use.  defaults to aes-128-cfb")
	flag.StringVar(&option.mode, "mode", "tcp+http+kcp", "option modes can be tcp http kcp,default tcp+http+kcp")
	flag.Parse()

	//work with heroku
	envport := os.Getenv("PORT")
	if envport != "" {
		iPort, err := strconv.ParseInt(envport, 10, 32)
		if err == nil {
			option.httpport = int(iPort)
		}
	}

	var end_waiter sync.WaitGroup
	bindAddr := fmt.Sprintf("%s:%d", option.bind, option.port) //"0.0.0.0:6566"
	if strings.Contains(option.mode, "tcp") {
		go servAsTCP(bindAddr)
		end_waiter.Add(1)
	}
	bindAddr = fmt.Sprintf("%s:%d", option.bind, option.httpport) //"0.0.0.0:6566"
	if strings.Contains(option.mode, "kcp") {
		go servAsKCP(bindAddr)
		end_waiter.Add(1)
	}
	if strings.Contains(option.mode, "http") {

		go servAsHttp(bindAddr)
		end_waiter.Add(1)
	}
	end_waiter.Wait()
	//fmt.Printf("%+v\n", x)

}
