package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func GenCert(sni string) {
	// 1. Generate Root CA
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pubBytes, _ := x509.MarshalPKIXPublicKey(&caPriv.PublicKey)
	skid := sha1.Sum(pubBytes)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NaiveProxy Local CA"},
			CommonName:   "NaiveProxy Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          skid[:],
	}

	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	savePEM("rootCA.crt", "CERTIFICATE", caBytes)
	saveKey("rootCA.key", caPriv)

	// 2. Generate Server Cert (sni)
	servPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	servPubBytes, _ := x509.MarshalPKIXPublicKey(&servPriv.PublicKey)
	servSkid := sha1.Sum(servPubBytes)

	servTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"NaiveProxy Server"},
			CommonName:   sni,
		},
		DNSNames:       []string{sni, "*." + sni},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		SubjectKeyId:   servSkid[:],
		AuthorityKeyId: skid[:],
	}

	servBytes, _ := x509.CreateCertificate(rand.Reader, servTemplate, caTemplate, &servPriv.PublicKey, caPriv)

	// ВАЖНО: Сохраняем ПОЛНУЮ цепочку (Leaf + Root) в один файл
	f, _ := os.Create(sni + ".crt")
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: servBytes})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	f.Close()

	saveKey(sni+".key", servPriv)
}

func savePEM(filename, typeStr string, bytes []byte) {
	f, _ := os.Create(filename)
	pem.Encode(f, &pem.Block{Type: typeStr, Bytes: bytes})
	f.Close()
}

func saveKey(filename string, key *ecdsa.PrivateKey) {
	f, _ := os.Create(filename)
	b, _ := x509.MarshalECPrivateKey(key)
	pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	f.Close()
}

