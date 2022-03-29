package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

var SINGLE = true

// simulate a client with this command :
// curl --trace trace.log -k --cacert ./CAcert.crt --cert ./cert.crt --key ./privateKey.key https://localhost:1234/

func main() {
	// point env variable to our CAcert so that computer does not point elsewhere
	os.Setenv("SSL_CERT_FILE", "./CAcert.crt")

	var tlsConfigSingle *tls.Config
	var tlsConfigDouble *tls.Config

	// tls config single way
	tlsConfigSingle = &tls.Config{InsecureSkipVerify: true}

	// tls config double way
	cert, err := tls.LoadX509KeyPair("./cert.crt", "./privateKey.key")
	if err != nil {
		panic(err)
	}
	CAcert, err := ioutil.ReadFile("./CAcert.crt")
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(CAcert)
	tlsConfigDouble = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientCAs:          caCertPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		InsecureSkipVerify: false,
	}
	tlsConfigDouble.BuildNameToCertificate()

	for {
		if SINGLE {
			fmt.Println("init new single connection")
			CONNECT := "127.0.0.1:1234"
			c, err := tls.Dial("tcp", CONNECT, tlsConfigSingle)
			if err != nil {
				fmt.Println(err)
				return
			}

			for {
				reader := bufio.NewReader(os.Stdin)
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println("error reading ", err)
				}
				fmt.Fprintf(c, text+"\n")

				message, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					fmt.Println("cannot read anything", err)
					time.Sleep(time.Duration(1) * time.Second)
					break
				}
				fmt.Print("->: " + message)
				if strings.TrimSpace(string(message)) == "STOP" {
					fmt.Println("cert request signed")
					SINGLE = false
					break
				}
			}
		} else {
			fmt.Println("init new double connection")
			CONNECT := "127.0.0.1:1234"
			c, err := tls.Dial("tcp", CONNECT, tlsConfigDouble)
			if err != nil {
				fmt.Println(err)
				return
			}

			for {
				reader := bufio.NewReader(os.Stdin)
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println("error reading ", err)
				}
				fmt.Fprintf(c, text+"\n")

				message, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					fmt.Println("cannot read anything", err)
					time.Sleep(time.Duration(1) * time.Second)
					break
				}
				fmt.Print("->: " + message)
				// if strings.TrimSpace(string(text)) == "STOP" {
				// 	fmt.Println("cert request signed")
				// 	break
				// }
			}
		}

	}

}
