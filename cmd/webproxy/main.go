package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/masa23/webproxy/config"
	"github.com/masa23/webproxy/rootca"
	"github.com/miekg/dns"
)

var (
	certs  = make(map[string]*tls.Certificate)
	rootCA *rootca.RootCA
	conf   *config.Config
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	// Statがエラーを返した場合は、ファイルが存在するかどうかわからないので、
	// 存在すると仮定する
	return true
}

func main() {
	var confPath string
	var err error

	flag.StringVar(&confPath, "conf", "config.yaml", "config file path")
	flag.Parse()

	// 設定ファイルを読み込む
	conf, err = config.LoadConfig(confPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	os.MkdirAll(conf.DumpDir, 0700)

	rootCA = rootca.New()
	// RootCAの秘密鍵と証明書が存在するか確認する
	if !fileExists(conf.RootCA.Key) || !fileExists(conf.RootCA.Cert) {
		// 存在しない場合は、RootCAの秘密鍵と証明書を生成する
		log.Println("generating root CA...")
		err := rootCA.Generate(conf.RootCA.Key, conf.RootCA.Cert)
		if err != nil {
			log.Fatalf("failed to generate root CA: %v", err)
		}
		err = rootCA.Save(conf.RootCA.Key, conf.RootCA.Cert)
		if err != nil {
			log.Fatalf("failed to save root CA: %v", err)
		}
	} else {
		// 存在する場合は、秘密鍵と証明書を読み込む
		log.Println("loading root CA...")
		err := rootCA.Load(conf.RootCA.Key, conf.RootCA.Cert)
		if err != nil {
			log.Fatalf("failed to load root CA: %v", err)
		}
	}

	go dnsServer()

	go func() {
		server := &http.Server{
			Addr: conf.ListenIPAddr + ":80",
		}
		server.Handler = http.HandlerFunc(proxy)
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("failed to listen and serve: %v", err)
		}
	}()

	server := &http.Server{
		Addr: conf.ListenIPAddr + ":443",
		TLSConfig: &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// ホスト名に対応する証明書が存在するか確認する
				cert, ok := certs[info.ServerName]
				if !ok {
					// 存在しない場合は、証明書を生成する
					log.Printf("generating server certificate for %s...", info.ServerName)
					cert, err = generateServerCertificate(info.ServerName)
					if err != nil {
						return nil, err
					}
					certs[info.ServerName] = cert
				}
				return cert, nil
			},
		},
	}
	server.Handler = http.HandlerFunc(proxy)

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("failed to listen and serve: %v", err)
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func proxy(w http.ResponseWriter, r *http.Request) {
	// methodがCONNECTの場合は
	if r.TLS == nil {
		r.URL.Scheme = "http"
	} else {
		r.URL.Scheme = "https"
	}
	if r.Method == http.MethodConnect {
		handleTunneling(w, r)
		return
	}
	r.URL.Host = r.Host
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// レスポンスヘッダをコピーする
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// ホスト名のディレクトリを作成する
	if !fileExists(conf.DumpDir + "/" + r.Host) {
		os.MkdirAll(conf.DumpDir+"/"+r.Host, 0700)
	}
	hash := md5.Sum([]byte(r.URL.String()))
	// リクエストをファイルに保存する
	freqh, err := os.Create(conf.DumpDir + "/" + r.Host + "/" + time.Now().Format("20060102150405") + "." + fmt.Sprintf("%016x", hash) + "_request_header.txt")
	if err != nil {
		log.Printf("failed to create file: %v", err)
		return
	}
	defer freqh.Close()
	r.Header.Write(freqh)
	// リクエストボディをファイルに保存する
	freqb, err := os.Create(conf.DumpDir + "/" + r.Host + "/" + time.Now().Format("20060102150405") + "." + fmt.Sprintf("%016x", hash) + "_request_body.txt")
	if err != nil {
		log.Printf("failed to create file: %v", err)
		return
	}
	defer freqb.Close()
	io.Copy(freqb, r.Body)

	// レスポンスをファイルに保存する
	fresph, err := os.Create(conf.DumpDir + "/" + r.Host + "/" + time.Now().Format("20060102150405") + "." + fmt.Sprintf("%016x", hash) + "_response_header.txt")
	if err != nil {
		log.Printf("failed to create file: %v", err)
		return
	}
	defer fresph.Close()
	resp.Header.Write(fresph)

	// レスポンスボディをファイルに保存する
	fb, err := os.Create(conf.DumpDir + "/" + r.Host + "/" + time.Now().Format("20060102150405") + "." + fmt.Sprintf("%016x", hash) + "_response_body.txt")
	if err != nil {
		log.Printf("failed to create file: %v", err)
		return
	}
	defer fb.Close()
	mw := io.MultiWriter(fb, w)
	io.Copy(mw, resp.Body)

	log.Printf("%s %s %s %d", r.RemoteAddr, r.Method, r.URL, resp.StatusCode)
}

func dnsServer() {
	go func() {
		server := &dns.Server{
			Addr: conf.ListenIPAddr + ":53",
			Net:  "udp",
		}
		server.Handler = dns.HandlerFunc(respdns)
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("failed to listen and serve: %v", err)
		}
	}()
	go func() {
		server := &dns.Server{
			Addr: conf.ListenIPAddr + ":53",
			Net:  "tcp",
		}
		server.Handler = dns.HandlerFunc(respdns)
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("failed to listen and serve: %v", err)
		}
	}()
}

func respdns(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			rr, err := dns.NewRR(q.Name + " 60 A " + conf.ListenIPAddr)
			if err != nil {
				log.Printf("failed to create RR: %v", err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		}
	}
	w.WriteMsg(m)
}

func generateServerCertificate(host string) (*tls.Certificate, error) {
	// 秘密鍵を生成する
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// 証明書のテンプレートを作成する
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"JP"},
			Organization: []string{"OreOre"},
			CommonName:   host,
		},
		NotBefore: time.Now().Add(-10 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		DNSNames:  []string{host},
		PublicKey: key.PublicKey,
	}

	// 証明書を発行する
	cert, err = rootCA.IssueServerCert(cert, &key.PublicKey)
	if err != nil {
		return nil, err
	}

	// tls.Certificateを作成する
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	return tlsCert, nil
}
