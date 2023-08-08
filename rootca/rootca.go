package rootca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

type RootCA struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

func New() *RootCA {
	return &RootCA{}
}

func (r *RootCA) Load(keyPath, certPath string) error {
	key, cert, err := LoadRootCA(keyPath, certPath)
	if err != nil {
		return err
	}
	r.Key = key
	r.Cert = cert
	return nil
}

func (r *RootCA) Generate(keyPath, certPath string) error {
	key, cert, err := GenerateRootCA()
	if err != nil {
		return err
	}
	r.Key = key
	r.Cert = cert
	return nil
}

func (r *RootCA) Save(keyPath, certPath string) error {
	err := SaveKey(r.Key, keyPath)
	if err != nil {
		return err
	}
	err = SaveCert(r.Cert, certPath)
	if err != nil {
		return err
	}
	return nil
}

func (r *RootCA) IssueServerCert(cert *x509.Certificate, pubKey *rsa.PublicKey) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, cert, r.Cert, pubKey, r.Key)
	if err != nil {
		return nil, err
	}

	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// root.keyとroot.crtを生成する
func GenerateRootCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	// Root CAの秘密鍵を生成する
	// RSA 2048bit
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// 証明書のテンプレートを作成
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"JP"},
			Organization: []string{"OreOre Root CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// 証明書を自己署名する
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	// DERをx509に変換する
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func LoadRootCA(keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// 秘密鍵を読み込む
	key, err := LoadKey(keyPath)
	if err != nil {
		return nil, nil, err
	}

	// 証明書を読み込む
	cert, err := LoadCert(certPath)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func LoadKey(path string) (*rsa.PrivateKey, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func LoadCert(path string) (*x509.Certificate, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func SaveKey(key *rsa.PrivateKey, path string) error {
	// 秘密鍵はパーミッション600で保存する
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func SaveCert(cert *x509.Certificate, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}
