package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// udpSession хранит состояние UDP-relay для одного клиента (IP:port).
type udpSession struct {
	clientAddr *net.UDPAddr
	backend    *net.UDPConn
}

type quicFrontend struct {
	conn       *net.UDPConn
	filter     *allowedIPFilter
	sni        string
	backend    string
	mode       string
	sessions   map[string]*udpSession
	sessionsMu sync.RWMutex
}

// bufferedConn позволяет "подсмотреть" данные и вернуть их обратно
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type allowedIPFilter struct {
	mu      sync.RWMutex
	allowed map[string]bool
}

func (f *allowedIPFilter) normalizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func (f *allowedIPFilter) isAllowed(ip string) bool {
	normalized := f.normalizeIP(ip)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.allowed) == 0 {
		return false
	}
	return f.allowed[normalized]
}

func (f *allowedIPFilter) addAllowed(ip string) {
	normalized := f.normalizeIP(ip)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.allowed == nil {
		f.allowed = make(map[string]bool)
	}
	f.allowed[normalized] = true
	log.Printf("IP %s активирован", normalized)
}

type ipFilterListener struct {
	inner   net.Listener
	filter  *allowedIPFilter
	sni     string
	mode    string
	authKey []byte
}

func (l *ipFilterListener) Close() error {
	return l.inner.Close()
}

func (l *ipFilterListener) Addr() net.Addr {
	return l.inner.Addr()
}

func (l *ipFilterListener) isValidClient(br *bufio.Reader, host string) bool {
	// Пытаемся прочитать TLS Client Hello достаточно глубоко, чтобы найти SessionID
	// Record Header (5) + Handshake Type(1) + Length(3) + Version(2) + Random(32) + SessionID Length(1)
	// Итого минимум 44 байта до SessionID
	const minHelloLen = 44 + 32
	peekLen := 512 // Берем с запасом
	data, err := br.Peek(peekLen)
	if err != nil {
		return false
	}

	// Проверяем TLS Handshake + Client Hello
	if data[0] != 0x16 || data[5] != 0x01 {
		return false
	}

	// Ищем SessionID
	// Смещение SessionID Length: 5 (Record) + 1 (Type) + 3 (Len) + 2 (Ver) + 32 (Random) = 43
	sessionIdLen := int(data[43])
	if sessionIdLen != 32 {
		return false
	}

	sessionId := data[44 : 44+32]

	// [0:5]  = random (5 байт)
	// [5:8]  = минуты с начала года (3 байта, big-endian)
	// [8:32] = HMAC (24 байта)

	randomBytes := sessionId[0:5]
	minutesBytes := sessionId[5:8]
	receivedMac := sessionId[8:32]

	// Преобразуем 3 байта минут в uint32
	minutesSinceYearStart := uint32(minutesBytes[0])<<16 |
		uint32(minutesBytes[1])<<8 |
		uint32(minutesBytes[2])

	// Восстанавливаем примерное время
	yearStart := time.Date(time.Now().Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	clientTime := yearStart.Add(time.Duration(minutesSinceYearStart) * time.Minute)

	// Проверяем временное окно (± 2.5 минуты, т.к. используем минуты)
	now := time.Now().UTC()
	if now.Sub(clientTime).Abs() > 2*time.Minute+30*time.Second {
		return false
	}

	// Проверяем HMAC
	mac := hmac.New(sha256.New, l.authKey)
	mac.Write(randomBytes)
	mac.Write(minutesBytes)
	mac.Write([]byte(l.sni))
	expectedMac := mac.Sum(nil)[:24]

	if !hmac.Equal(receivedMac, expectedMac) {
		return false
	}

	// Успешная проверка → добавляем IP в белый список
	l.filter.addAllowed(host)
	return true
}

func (l *ipFilterListener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		br := bufio.NewReader(c)

		// 1. Уже в белом списке
		// 2. Успешный "стук" через SessionID
		// 3. Официальный режим (пропускаем всех до ServeHTTP)
		if l.filter.isAllowed(host) || l.isValidClient(br, host) || l.mode == "official" {
			return &bufferedConn{Conn: c, r: br}, nil
		}

		// Если никто не подошел - прикидываемся голым TCP-туннелем
		go l.transparentToSni(c, br)
	}
}

func (l *ipFilterListener) transparentToSni(client net.Conn, br *bufio.Reader) {
	defer client.Close()
	remote, err := net.Dial("tcp", l.sni+":443")
	if err != nil {
		return
	}
	defer remote.Close()

	// Пересылаем то, что уже успели прочитать в буфер
	if br.Buffered() > 0 {
		peeked, _ := br.Peek(br.Buffered())
		remote.Write(peeked)
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
}

func (q *quicFrontend) sessionKey(addr *net.UDPAddr) string {
	return addr.String()
}

func isQuicInitial(packet []byte) bool {
	if len(packet) < 6 {
		return false
	}
	return (packet[0]&0xC0 == 0xC0) && ((packet[0]>>4)&0x03 == 0x00)
}

func (q *quicFrontend) Start(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	if err := conn.SetReadBuffer(4 * 1024 * 1024); err != nil {
		log.Printf("QUIC Frontend: не удалось установить ReadBuffer: %v", err)
	}
	if err := conn.SetWriteBuffer(4 * 1024 * 1024); err != nil {
		log.Printf("QUIC Frontend: не удалось установить WriteBuffer: %v", err)
	}

	q.conn = conn
	q.sessions = make(map[string]*udpSession)

	log.Printf("QUIC Frontend запущен на %s (маскировка под %s)", addr, q.sni)

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("QUIC Frontend read error: %v", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		go q.handlePacket(packet, clientAddr)
	}
}

func (q *quicFrontend) handlePacket(packet []byte, clientAddr *net.UDPAddr) {
	q.sessionsMu.RLock()
	sess := q.sessions[q.sessionKey(clientAddr)]
	q.sessionsMu.RUnlock()

	if sess != nil {
		sess.backend.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := sess.backend.Write(packet); err != nil {
			log.Printf("[quicFrontend] write to backend: %v", err)
		}
		return
	}

	if !isQuicInitial(packet) {
		return
	}

	clientIP := clientAddr.IP.String()
	if q.filter.isAllowed(clientIP) {
		q.forward(packet, clientAddr, q.backend, "quic-backend")
	} else {
		q.forward(packet, clientAddr, q.sni+":443", "fallback")
	}
}

func (q *quicFrontend) forward(packet []byte, clientAddr *net.UDPAddr, target string, label string) {
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("[quicFrontend] resolve %s: %v", target, err)
		return
	}

	backend, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("[quicFrontend] dial %s: %v", target, err)
		return
	}

	backend.SetReadBuffer(2 * 1024 * 1024)
	backend.SetWriteBuffer(2 * 1024 * 1024)

	if _, err := backend.Write(packet); err != nil {
		log.Printf("[quicFrontend] write to %s: %v", label, err)
		backend.Close()
		return
	}

	sess := &udpSession{
		clientAddr: clientAddr,
		backend:    backend,
	}
	q.sessionsMu.Lock()
	q.sessions[q.sessionKey(clientAddr)] = sess
	q.sessionsMu.Unlock()

	go q.proxyUDP(sess, label)
}

func (q *quicFrontend) proxyUDP(sess *udpSession, label string) {
	defer func() {
		q.sessionsMu.Lock()
		if q.sessions[q.sessionKey(sess.clientAddr)] == sess {
			delete(q.sessions, q.sessionKey(sess.clientAddr))
		}
		q.sessionsMu.Unlock()
		sess.backend.Close()
	}()

	buf := make([]byte, 65535)
	for {
		sess.backend.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, _, err := sess.backend.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[quicFrontend] %s proxy timeout", label)
			} else {
				log.Printf("[quicFrontend] %s proxy read: %v", label, err)
			}
			return
		}

		if _, err := q.conn.WriteToUDP(buf[:n], sess.clientAddr); err != nil {
			log.Printf("[quicFrontend] write to client %s: %v", sess.clientAddr, err)
			return
		}
	}
}
