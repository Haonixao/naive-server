package main

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// server struct для хранения http.Transport
type server struct {
	tr      *http.Transport
	sni     string
	filter  *allowedIPFilter
	authKey []byte
	mode    string
	padding string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// В официальном режиме мы позволяем TLS-рукопожатию завершиться для всех,
	// чтобы зонд мог увидеть нашу страницу
	if s.mode == "official" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)

		// Если это Naive CONNECT и IP в белом списке - даем доступ
		if r.Method == http.MethodConnect && s.filter.isAllowed(host) {
			s.handleConnect(w, r)
			return
		}

		// Для всех остальных (зонды, браузеры, неавторизованный CONNECT) - выдаем заглушку
		s.serveDecoy(w)
		return
	}

	// В stealth режиме (только для тех, кто прошел Accept)
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	s.handleRequest(w, r)
}

func (s *server) serveDecoy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(DecoyHTML))
}

func main() {
	// Загружаем decoy.html
	content, err := os.ReadFile("decoy.html")
	if err != nil {
		log.Printf("ВНИМАНИЕ: Не удалось прочитать decoy.html, использую заглушку по умолчанию: %v", err)
		DecoyHTML = "<h1>Technical Maintenance</h1>"
	} else {
		DecoyHTML = string(content)
	}

	mode := flag.String("mode", "stealth", "Режим работы: stealth (самоподписанные) или official (Let's Encrypt)")
	sni := flag.String("sni", "go.dev", "SNI для маскировки")
	padding := flag.String("padding", "1", "тип padding для данных")
	flag.Parse()

	if *padding == "2" {
		NumFirstPaddings = -1
	}

	// Генерируем секретный ключ для HMAC (32 байта)
	authKey := make([]byte, 32)
	if _, err := rand.Read(authKey); err != nil {
		log.Fatalf("Ошибка генерации ключа: %v", err)
	}

	filter := &allowedIPFilter{allowed: make(map[string]bool)}

	var cert tls.Certificate

	if *mode == "official" {
		log.Printf("Запуск в режиме OFFICIAL. Ожидаются сертификаты для: %s", *sni)
		// В официальном режиме используем реальные сертификаты
		cert, err = tls.LoadX509KeyPair(*sni+".crt", *sni+".key")
		if err != nil {
			log.Printf("ОШИБКА: В режиме official нужно заранее положить сертификаты %s.crt и %s.key (например от Certbot)", *sni, *sni)
			log.Fatalf("Или используйте stealth режим для автогенерации.")
		}
	} else {
		cert, err = tls.LoadX509KeyPair(*sni+".crt", *sni+".key")
		if err != nil {
			log.Printf("Не удалось загрузить cert/key: %v", err)
			GenCert(*sni)
			cert, err = tls.LoadX509KeyPair(*sni+".crt", *sni+".key")
			if err != nil {
				log.Fatalf("Критическая ошибка: даже после генерации сертификаты не загрузились: %v", err)
			}
			log.Printf("Сгенерированы новые %s + %s", *sni+".crt/"+*sni+".key", "rootCA.crt/rootCA.key")
			log.Printf("%s ДОЛЖНЫ находится рядом с запускаемым сервером", *sni+".crt/"+*sni+".key")
		}
	}

	// Общий конфиг для TLS
	baseTlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Конфиг для HTTP/2 (TCP)
	h2TlsCfg := baseTlsCfg.Clone()
	h2TlsCfg.NextProtos = []string{"h2", "http/1.1"}

	l, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	f := &ipFilterListener{
		inner:   l,
		filter:  filter,
		sni:     *sni,
		authKey: authKey,
		mode:    *mode,
	}

	// Инициализируем http.Transport
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Создаем экземпляр нашей структуры server
	s := &server{
		tr:      tr,
		sni:     *sni,
		filter:  filter,
		mode:    *mode,
		authKey: authKey,
		padding: *padding,
	}

	// Создаем http.Server с базовыми таймаутами
	httpServer := &http.Server{
		Addr:              ":443",
		Handler:           s,
		TLSConfig:         h2TlsCfg,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       1 * time.Minute,
	}

	// Явно настраиваем HTTP/2 для httpServer с оптимизированными параметрами
	h2srv := &http2.Server{
		MaxConcurrentStreams: 1000,
		MaxReadFrameSize:     1024 * 1024,
		IdleTimeout:          10 * time.Minute,
	}

	if err := http2.ConfigureServer(httpServer, h2srv); err != nil {
		log.Fatalf("Ошибка настройки HTTP/2: %v", err)
	}

	if *mode == "official" {
		// Конфиг для HTTP/3 (QUIC)
		h3TlsCfg := baseTlsCfg.Clone()
		h3TlsCfg.NextProtos = []string{"h3"}   // QUIC-GO требует h3
		h3TlsCfg.MinVersion = tls.VersionTLS13 // QUIC требует TLS 1.3
		// 1. Запускаем QUIC Backend (HTTP/3)
		h3srv := &http3.Server{
			Addr:      ":443",
			Handler:   s,
			TLSConfig: h3TlsCfg,
			QUICConfig: &quic.Config{
				MaxIdleTimeout:     10 * time.Minute,
				MaxIncomingStreams: 1000, // Совпадает с настройкой HTTP/2
				EnableDatagrams:    true,
			},
		}
		go func() {
			log.Printf("QUIC Backend (HTTP/3) запущен на %s", h3srv.Addr)
			if err := h3srv.ListenAndServe(); err != nil {
				log.Printf("QUIC Backend error: %v", err)
			}
		}()
	} else {
		q := &quicFrontend{
			filter:  filter,
			sni:     *sni,
			mode:    *mode,
			backend: "127.0.0.1:8443",
		}
		go q.Start(":443")

		h3TlsCfg := baseTlsCfg.Clone()
		h3TlsCfg.NextProtos = []string{"h3"}
		h3TlsCfg.MinVersion = tls.VersionTLS13

		h3srv := &http3.Server{
			Addr:      "127.0.0.1:8443",
			Handler:   s,
			TLSConfig: h3TlsCfg,
			QUICConfig: &quic.Config{
				MaxIdleTimeout:     10 * time.Minute,
				MaxIncomingStreams: 1000,
				EnableDatagrams:    true,
			},
		}
		go func() {
			log.Printf("QUIC Backend (HTTP/3) [stealth] запущен на %s", h3srv.Addr)
			if err := h3srv.ListenAndServe(); err != nil {
				log.Printf("QUIC Backend error: %v", err)
			}
		}()
	}

	log.Printf("naive_server (exit node) запущен на :443 SNI=%s", *sni)
	log.Printf("AUTH KEY (HEX): %x", authKey)
	log.Fatal(httpServer.Serve(tls.NewListener(f, h2TlsCfg)))
}
