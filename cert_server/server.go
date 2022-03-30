package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	// "strconv"
	"strings"
)

// program based on this site :
// https://www.linode.com/docs/guides/developing-udp-and-tcp-clients-and-servers-in-go/#test-the-concurrent-tcp-server

// var count = 0
var SINGLE = false

func handleSingleConnection(c *tls.Conn) {
	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println("error reading single :", err)
			break
		}
		fmt.Println("<", netData)

		temp := strings.TrimSpace(string(netData))
		if temp == "CERT_REQUEST" {
			c.Write([]byte("REQUEST_SIGNED\n")) // certificats créés
			fmt.Println("... signing CERT_REQUEST ...")
			c.Close()
			break
		} else {
			c.Write([]byte("unknown command\n")) // certificats créés
		}
	}

}

func handleDoubleConnection(c *tls.Conn) {
	fmt.Println("inside doubleway loop")
	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println("error reading double :", err)
			break
		}

		temp := strings.TrimSpace(string(netData))
		// if temp == "STOP" {
		// 	break
		// }
		fmt.Println("<<", temp)
		// counter := strconv.Itoa(count) + "\n"
		// c.Write([]byte(string(counter)))
	}
	c.Close()
}

func main() {
	// point env variable to our CAcert so that computer does not point elsewhere
	os.Setenv("SSL_CERT_FILE", "./CAcert.crt")

	PORT := ":1234"
	l, err := net.Listen("tcp", PORT)
	if err != nil {
		fmt.Println("error listen :", err)
		return
	}
	defer l.Close()

	var tlsConfigSingle *tls.Config
	var tlsConfigDouble *tls.Config

	// tls config single way
	certSingle, err := tls.LoadX509KeyPair("./cert.crt", "./privateKey.key")
	if err != nil { // only client in insecure mode
		fmt.Println("! Unable to Load certificate !")
		tlsConfigSingle = &tls.Config{InsecureSkipVerify: true}
	} else {
		tlsConfigSingle = &tls.Config{
			Certificates:       []tls.Certificate{certSingle},
			InsecureSkipVerify: false,
		}
	}

	// tls Double way
	CAcert, err := ioutil.ReadFile("../cert_server/CAcert.crt")
	if err != nil {
		fmt.Println("error read file cacert :", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(CAcert)
	tlsConfigDouble = &tls.Config{
		Certificates:       []tls.Certificate{certSingle},
		ClientCAs:          caCertPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		InsecureSkipVerify: false,
	}
	tlsConfigDouble.BuildNameToCertificate()

	SinglePeers := make(map[string]bool)
	var tlsConn *tls.Conn

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Printf("serverShoset accept error: %s", err)
			continue
		}

		address_port := c.RemoteAddr().String()
		address_parts := strings.Split(address_port, ":")
		address := address_parts[0]
		// fmt.Println("address detected : ", address)

		if SinglePeers[address] {
			// fmt.Println("trying single way")
			tlsConn = tls.Server(c, tlsConfigSingle)
			_, err = tlsConn.Write([]byte("hello single\n"))
			delete(SinglePeers, address)
			if err == nil {
				// fmt.Println("going for single")
				go handleSingleConnection(tlsConn)
			} else {
				fmt.Println("err single : ", err)
				tlsConn.Close()
			}
		} else {
			// fmt.Println("trying double way")
			tlsConn = tls.Server(c, tlsConfigDouble) // create the securised connection protocol
			_, err = tlsConn.Write([]byte("hello double\n"))
			if err == nil {
				go handleDoubleConnection(tlsConn)
			} else {
				fmt.Println("err double : ", err)
				SinglePeers[address] = true
				tlsConn.Close()
			}
		}
		// count++
	}
}
