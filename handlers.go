package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// handleConnect — обработка CONNECT для exit-узла (dumb pipe)
func (s *server) handleConnect(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if target == "" {
		log.Printf("handleConnect: Bad Request - empty target for %s %s", r.Method, r.URL)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Printf("CONNECT from %s: %s", r.RemoteAddr, target)

	// Передаем заголовок Padding-Type-Reply, если клиент запросил паддинг
	if r.Header.Get("Padding") != "" {
		w.Header().Set("Padding-Type-Reply", s.padding)
	}

	dialer := net.Dialer{Timeout: 30 * time.Second}
	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("handleConnect: dial to %s failed: %v", target, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	targetConn = &timeoutConn{Conn: targetConn}
	defer closeWrite(targetConn)

	// Отправляем 200 и сразу flush (критично для низкой задержки)
	w.WriteHeader(http.StatusOK)

	// ВАЖНО: Принудительно отправляем заголовки сейчас
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	rc := http.NewResponseController(w)

	// FullDuplex не работает с QUIC
	if s.mode != "official" {
		if err := rc.EnableFullDuplex(); err != nil {
			log.Printf("handleConnect: EnableFullDuplex failed: %v", err)
			return
		}
	}

	if err := rc.Flush(); err != nil {
		log.Printf("handleConnect: Flush after 200 failed: %v", err)
		return
	}

	// Запускаем bidirectional stream
	if err := dualStream(targetConn, r.Body, w, r.Header.Get("Padding") != ""); err != nil {
		log.Printf("handleConnect: dualStream error: %v", err)
	}
}

// handleRequest — обработка обычных HTTP-запросов
func (s *server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Если это запрос к нам самим (например, проверка от naive или браузера),
	// отвечаем 200 OK без проксирования, чтобы избежать зацикливания.
	if r.URL.Path == "/" && (r.Host == "" || strings.Contains(r.Host, s.sni)) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	log.Printf("%s from %s: %s", r.Method, r.RemoteAddr, r.URL.Host)

	// Удаляем hop-by-hop заголовки из запроса
	removeHopByHop(r.Header)

	// Устанавливаем RequestURI в пустую строку, как того ожидает http.Transport
	r.RequestURI = ""

	// Выполняем запрос через http.Transport
	resp, err := s.tr.RoundTrip(r)
	if err != nil {
		log.Printf("handleRequest: RoundTrip error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Пересылаем ответ клиенту
	forwardResponse(w, resp)
}

// removeHopByHop удаляет hop-by-hop заголовки из HTTP-заголовков.
func removeHopByHop(header http.Header) {
	connectionHeaders := header.Get("Connection")
	for _, h := range strings.Split(connectionHeaders, ",") {
		header.Del(strings.TrimSpace(h))
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

var hopByHopHeaders = []string{
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Upgrade",
	"Connection",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
}

// forwardResponse пересылает HTTP-ответ клиенту.
func forwardResponse(w http.ResponseWriter, response *http.Response) {
	// Копируем заголовки ответа, исключая hop-by-hop
	for header, values := range response.Header {
		for _, val := range values {
			w.Header().Add(header, val)
		}
	}
	removeHopByHop(w.Header())

	// Устанавливаем статус-код
	w.WriteHeader(response.StatusCode)

	// Копируем тело ответа
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[0:cap(buf)]
	_, err := io.CopyBuffer(w, response.Body, buf)
	bufferPool.Put(bufPtr)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
	}
}
