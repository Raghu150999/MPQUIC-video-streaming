package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os/exec"

	"github.com/lucas-clemente/quic-go"
)

// CHUNK size to read
const CHUNK = 1024 * 10

func main() {
	addr := "localhost:8000"
	filename := "test.mp4"
	client(addr, filename)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func client(addr string, filename string) {
	// setup multipath configuration
	quicConfig := &quic.Config{
		CreatePaths: true,
	}
	// connect to server
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, quicConfig)
	check(err)
	stream, err := session.OpenStreamSync()
	defer stream.Close()

	// initiate SETUP
	sendMessage("SETUP", stream)

	// send filename
	sendMessage(filename, stream)

	// get reponse
	msg := readMessage(stream)
	if msg != "OK" {
		return
	}

	// start ffmpeg
	ffmpeg := exec.Command("ffplay", "-f", "mp4", "-i", "pipe:")
	inpipe, err := ffmpeg.StdinPipe()
	check(err)
	err = ffmpeg.Start()

	// write
	_, err = io.Copy(inpipe, stream)
	if err != nil {
		fmt.Println("Stream closed...")
	}
	fmt.Println("Exited...")
	ffmpeg.Wait()
}

func sendMessage(msg string, stream quic.Stream) {
	// utility for sending control messages
	l := uint32(len(msg))
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, l)
	stream.Write(data)
	stream.Write([]byte(msg))
}

func readMessage(stream quic.Stream) string {
	// utility for receiving control messages
	data := make([]byte, 4)
	stream.Read(data)
	l := binary.LittleEndian.Uint32(data)
	data = make([]byte, l)
	stream.Read(data)
	return string(data)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
