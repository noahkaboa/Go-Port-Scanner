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
)

var IP string

type SafePortMap struct {
	mu    sync.Mutex
	ports map[int]string
}

func main() {
	flag.StringVar(&IP, "n", "127.0.0.1", "IP Address/network to scan")
	flag.Parse()

	IP = "nmap.org"

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
	v, e := tcp_scan(IP, port)
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

// func ReadConnection(conn net.Conn) []byte {
// 	tmp := make([]byte, 1024)
// 	data := make([]byte, 0)

// 	length := 0

// 	for {
// 		n, err := conn.Read(tmp)
// 		if err != nil {
// 			if err != io.EOF {
// 				fmt.Println("Read error: ", err)
// 			} else {
// 				fmt.Println("Reached EOF")
// 			}
// 			break
// 		}
// 		data = append(data, tmp[:n]...)
// 		length += n
// 	}
// 	fmt.Printf("Got %d bytes\n", length)
// 	return data
// }

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
