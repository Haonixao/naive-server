package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	mrand "math/rand"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	mrand.New(mrand.NewSource(time.Now().UnixNano()))
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

	// 1. Вычисляем минуты с начала текущего года (UTC)
	now := time.Now().UTC()
	yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	minutesSinceYearStart := uint32(now.Sub(yearStart).Minutes())

	// 2. Генерируем 5 случайных байт
	randomBytes := make([]byte, 5)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}

	// 3. Упаковываем минуты в 3 байта (big-endian)
	minutesBytes := make([]byte, 3)
	minutesBytes[0] = byte(minutesSinceYearStart >> 16)
	minutesBytes[1] = byte(minutesSinceYearStart >> 8)
	minutesBytes[2] = byte(minutesSinceYearStart)

	// 4. Считаем HMAC(key, random + минуты + SNI)
	mac := hmac.New(sha256.New, key)
	mac.Write(randomBytes)
	mac.Write(minutesBytes)
	mac.Write([]byte(*sni))
	fullMac := mac.Sum(nil)

	// 5. Собираем SessionID (32 байта)
	sessionId := make([]byte, 32)
	copy(sessionId[0:5], randomBytes)
	copy(sessionId[5:8], minutesBytes)
	copy(sessionId[8:32], fullMac[:24])

	log.Printf("Activating %s (SNI: %s)...", *ip, *sni)

	// 2. Connect via TCP
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(*ip, "443"), 30*time.Second)
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

	// Рандомная задержка от 1 до 4 секунд
	delay := time.Duration(1+mrand.Intn(4)) * time.Second
	time.Sleep(delay)

	log.Printf("SUCCESS: Activation completed !")
	log.Println("Now you can use naiveproxy client to connect.")
}
