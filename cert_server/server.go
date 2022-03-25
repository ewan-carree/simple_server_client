package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
)

// program based on this site :
// https://www.linode.com/docs/guides/developing-udp-and-tcp-clients-and-servers-in-go/#test-the-concurrent-tcp-server

var count = 0
var SINGLE = true

func handleConnection(c *tls.Conn) {
	fmt.Print(".")
	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println("{{{", err)
			return
		}

		temp := strings.TrimSpace(string(netData))
		if temp == "STOP" {
			break
		}
		fmt.Println(temp)
		counter := strconv.Itoa(count) + "\n"
		c.Write([]byte(string(counter)))
	}
	c.Close()
}

func main() {
	// point env variable to our CAcert so that computer does not point elsewhere
	os.Setenv("SSL_CERT_FILE", "./CAcert.crt")

	PORT := ":1234"
	l, err := net.Listen("tcp", PORT)
	if err != nil {
		fmt.Println("!!!", err)
		return
	}
	defer l.Close()

	var tlsConfig *tls.Config
	if SINGLE {
		// tls config single way
		certSingle, err := tls.LoadX509KeyPair("./cert.crt", "./privateKey.key")
		if err != nil { // only client in insecure mode
			fmt.Println("! Unable to Load certificate !")
			tlsConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			tlsConfig = &tls.Config{
				Certificates:       []tls.Certificate{certSingle},
				InsecureSkipVerify: false,
			}
		}
	} else {
		// tls config double way
		certDouble, err := tls.LoadX509KeyPair("/mnt/c/Users/carre/Desktop/simple_server_client/cert_server/cert.crt", "/mnt/c/Users/carre/Desktop/simple_server_client/cert_server/privateKey.key")
		if err != nil {
			fmt.Println("~~~~~~~~", err)
		}
		CAcert, err := ioutil.ReadFile("../cert_server/CAcert.crt")
		if err != nil {
			fmt.Println("00000000")
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(CAcert)
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{certDouble},
			ClientCAs:          caCertPool,
			ClientAuth:         tls.RequireAndVerifyClientCert,
			InsecureSkipVerify: false,
		}
		tlsConfig.BuildNameToCertificate()
	}

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Printf("serverShoset accept error: %s", err)
			break
		}
		tlsConn := tls.Server(c, tlsConfig) // create the securised connection protocol
		// a := tlsConn.ConnectionState()
		// fmt.Println(a)
		// tlsConn = tls.Server(c, tlsConfig)
		// b:= tlsConn.ConnectionState
		// fmt.Println(b)
		// w := bufio.NewWriter(tlsConn)
		// tlsConn.Write(w.WriteString("init"))
		_, err = tlsConn.Write([]byte("hello\n"))
		if err != nil {
			fmt.Println("err : ", err)
		}
		// s := msg.NewWriter()
		// if err != nil {
		// 	tlsConn = tls.Server(c, tlsConfig)
		// 	_, err = tlsConn.Write([]byte("init"))
		// 	if err != nil {
		// 		fmt.Println("still not working", err)
		// 		return
		// 	} else {
		// 		fmt.Println("ok single way")
		// 	}
		// } else {
		// 	fmt.Println("ok double way")
		// }

		go handleConnection(tlsConn)
		count++
	}
}
