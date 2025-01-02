package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

var IP string

type SafePortMap struct {
	mu    sync.Mutex
	ports map[int]string
}

func (spm *SafePortMap) addPort(port int, body string) {
	spm.mu.Lock()
	spm.ports[port] = body
	spm.mu.Unlock()
}

func (spm *SafePortMap) getPort(port int) string {
	spm.mu.Lock()
	defer spm.mu.Unlock()
	return spm.ports[port]
}

func main() {
	flag.StringVar(&IP, "n", "127.0.0.1", "IP Address/network to scan")
	flag.Parse()

	IP = "64.13.134.52"

	scan_results := SafePortMap{ports: make(map[int]string)}

	tcp_ports_file, err := os.Open("tcp_ports.csv")
	if err != nil {
		fmt.Println("error opening file")
	}
	defer tcp_ports_file.Close()

	reader := csv.NewReader(tcp_ports_file)
	tcp_ports, e := reader.ReadAll()
	if e != nil {
		fmt.Println("error reading file")
		fmt.Println(e)
	}

	start := time.Now()

	for _, port := range tcp_ports {
		port_string := strings.Join(port, "")
		port_int, _ := strconv.Atoi(port_string)
		go scan_results.addPort(port_int, port_scan(IP, port_string))
	}

	t := time.Now()

	for _, port := range tcp_ports {
		port_string := strings.Join(port, "")
		port_int, _ := strconv.Atoi(port_string)
		fmt.Println(port_string + ":\t" + scan_results.getPort(port_int))
	}
	fmt.Printf("Took %v seconds\n", t.Sub(start))

}

func port_scan(IP string, port string) string {
	v, e := syn_scan(IP, port)
	if e != nil {
		if e, ok := e.(net.Error); ok && e.Timeout() {
			return "closed/filtered"
		}
		return "Something went wrong!"
	}
	return v
}

func tcp_scan(IP string, port string) (string, error) {
	// fmt.Println("IP is " + IP + ":" + port)
	timeoutDuration, timeErr := time.ParseDuration("1s")
	if timeErr != nil {
		fmt.Println("The time is wrong")
		return "", timeErr
	}
	c, e := net.DialTimeout("tcp", IP+":"+port, timeoutDuration)
	if e != nil {
		return "closed", e
	} else {
		defer c.Close() //necessary?
	}
	return "open", nil
}

// Uses raw socket
func syn_scan(IP string, port string) (string, error) {

	srcPortNum := 4444
	dstPortNum, _ := strconv.Atoi(port)

	fmt.Println(IP)
	dstIP := net.ParseIP(IP)
	if dstIP == nil {
		fmt.Println("not ip!")
		return "", nil
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		fmt.Println("Not v4 ip!")
		return "", nil
	}

	packetConn, connErr := net.ListenPacket("ip4:tcp", IP)
	if connErr != nil {
		fmt.Println("Went wrong making the connection")
		return "", nil
	}

	rawConn, rawErr := ipv4.NewRawConn(packetConn)
	if rawErr != nil {
		fmt.Println("Couldnt make a raw connection!")
		return "", nil
	}

	srcIP := packetConn.LocalAddr()

	ip := layers.IPv4{
		SrcIP:    net.IP(srcIP.String()),
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	srcport := layers.TCPPort(srcPortNum)
	dstport := layers.TCPPort(dstPortNum)

	tcp := layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Window:  1505,
		Urgent:  0,
		Seq:     11050,
		Ack:     0,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		RST:     false,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcp.SetNetworkLayerForChecksum(&ip)

	ipHeaderBuf := gopacket.NewSerializeBuffer()
	headerBufErr := ip.SerializeTo(ipHeaderBuf, opts)
	if headerBufErr != nil {
		fmt.Println("Couldnt serialize ip header!")
		return "", nil
	}
	ipHeader, headerErr := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if headerErr != nil {
		fmt.Println("Couldn't parse header!")
		return "", nil
	}
	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload([]byte("foobar"))
	packetErr := gopacket.SerializeLayers(tcpPayloadBuf, opts, &tcp, payload)
	if packetErr != nil {
		fmt.Println("Couldn't serialize the packet! ruhroh")
		return "", nil
	}

	sendErr := rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil)

	fmt.Println("Result: ")
	fmt.Println(sendErr)

	return "Done", nil

}
