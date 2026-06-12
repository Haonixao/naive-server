package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	ip := flag.String("ip", "", "IP address of naive_server")
	sni := flag.String("sni", "go.dev", "SNI to use for activation")
	keyHex := flag.String("key", "", "Auth Key in HEX format")
	flag.Parse()

	if *ip == "" || *keyHex == "" {
		log.Fatal("Usage: -ip <server_ip> -key <auth_key_hex> [-sni <sni>]")
	}

	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		log.Fatalf("Invalid key format: %v", err)
	}

	// 1. Prepare SessionID (8 bytes timestamp + 24 bytes HMAC)
	now := time.Now().Unix()
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(now))

	mac := hmac.New(sha256.New, key)
	mac.Write(tsBytes)
	mac.Write([]byte(*sni))
	fullMac := mac.Sum(nil)

	sessionId := make([]byte, 32)
	copy(sessionId[:8], tsBytes)
	copy(sessionId[8:], fullMac[:24])

	log.Printf("Activating %s (SNI: %s)...", *ip, *sni)

	// 2. Connect via TCP
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(*ip, "443"), 10*time.Second)
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer conn.Close()

	// 3. Use uTLS to send Client Hello with custom SessionID
	config := &utls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(conn, config, utls.HelloChrome_Auto)

	err = uConn.BuildHandshakeState()
	if err != nil {
		log.Fatalf("Failed to build handshake state: %v", err)
	}

	uConn.HandshakeState.Hello.SessionId = sessionId

	// 4. Perform Handshake
	uConn.SetDeadline(time.Now().Add(10 * time.Second))
	err = uConn.Handshake()
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}

	log.Printf("SUCCESS: Activation completed !")
	log.Println("Now you can use naiveproxy client to connect.")
}
