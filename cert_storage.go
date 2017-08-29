package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	_ "encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/pmylund/go-cache"
)

var redisCertificateStorage *RedisClusterStorageManager
var certificateCache = cache.New(10*time.Minute, 20*time.Minute)

var certLogger *logrus.Entry

func init() {
	redisCertificateStorage = &RedisClusterStorageManager{KeyPrefix: "cert-"}
	certLogger = log.WithFields(logrus.Fields{
		"prefix": "cert_storage",
	})
}

func privateCertificateEncodingSecret() string {
	if globalConf.Security.PrivateCertificateEncodingSecret != "" {
		return globalConf.Security.PrivateCertificateEncodingSecret
	}

	return globalConf.Secret
}

// Extracted from: https://golang.org/src/crypto/tls/tls.go
//
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

func isSHA256(value string) bool {
	// 32 SHA256 size * 2 Hex encoding
	if len(value) != 64 {
		return false
	}

	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}

	return true
}

func certSHA256(cert []byte) string {
	certSHA := sha256.Sum256(cert)
	return hex.EncodeToString(certSHA[:])
}

func parsePEM(data []byte) (*tls.Certificate, error) {
	var cert tls.Certificate
	var block *pem.Block
	var decrypted []byte
	var err error

	for {
		block, data = pem.Decode(data)

		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			cert.Certificate = append(cert.Certificate, block.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			decrypted, err = x509.DecryptPEMBlock(block, []byte(privateCertificateEncodingSecret()))
			if err != nil {
				return nil, err
			}

			cert.PrivateKey, err = parsePrivateKey(decrypted)
			if err != nil {
				return nil, err
			}
		default:
			if strings.HasSuffix(block.Type, "PRIVATE KEY") {
				cert.PrivateKey, err = parsePrivateKey(block.Bytes)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if len(cert.Certificate) == 0 {
		return nil, errors.New("Can't find CERTIFICATE block")
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])

	if err != nil {
		return nil, err
	}

	// Cache certificate fingerprint
	cert.Leaf.Extensions = append([]pkix.Extension{{
		Value: []byte(certSHA256(cert.Leaf.Raw)),
	}}, cert.Leaf.Extensions...)

	return &cert, nil
}

type certificateListMode int

const (
	withoutPrivateKeys certificateListMode = iota
	withPrivateKeys
)

func isPrivateKeyEmpty(cert *tls.Certificate) bool {
	switch priv := cert.PrivateKey.(type) {
	default:
		if priv == nil {
			return true
		}
	}

	return false
}

func isCertCanBeListed(cert *tls.Certificate, mode certificateListMode) bool {
	switch mode {
	case withPrivateKeys:
		return !isPrivateKeyEmpty(cert)
	case withoutPrivateKeys:
		return isPrivateKeyEmpty(cert)
	}

	return true
}

func fetchCertificates(certIDs []string, mode certificateListMode) (out []*tls.Certificate) {
	var cert *tls.Certificate
	var rawCert []byte
	var err error

	for _, id := range certIDs {
		if cert, found := certificateCache.Get(id); found {
			if isCertCanBeListed(cert.(*tls.Certificate), mode) {
				out = append(out, cert.(*tls.Certificate))
			}
			continue
		}

		if isSHA256(id) {
			var val string
			val, err = redisCertificateStorage.GetKey("raw-" + id)
			if err != nil {
				certLogger.Warn("Can't retrieve certificate from Redis:", id, err)
				continue
			}
			rawCert = []byte(val)
		} else {
			rawCert, err = ioutil.ReadFile(id)
			if err != nil {
				certLogger.Error("Error while reading certificate from file:", id, err)
				continue
			}
		}

		cert, err = parsePEM(rawCert)
		if err != nil {
			certLogger.Error("Error while parsing certificate: ", id, " ", err)
			continue
		}

		certificateCache.Set(id, cert, cache.DefaultExpiration)

		if isCertCanBeListed(cert, mode) {
			out = append(out, cert)
		}
	}

	return out
}

func addCertificate(certData []byte) (string, error) {
	var certBlocks [][]byte
	var keyPEM, keyRaw []byte
	var block *pem.Block

	rest := certData

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			if len(keyRaw) > 0 {
				err := errors.New("Found multiple private keys")
				certLogger.Error(err)
				return "", err
			}

			keyRaw = block.Bytes
			keyPEM = pem.EncodeToMemory(block)
		} else if block.Type == "CERTIFICATE" {
			certBlocks = append(certBlocks, pem.EncodeToMemory(block))
		} else {
			certLogger.Info("Ingoring PEM block with type:", block.Type)
		}
	}

	certChainPEM := bytes.Join(certBlocks, []byte("\n"))

	if len(certChainPEM) == 0 {
		err := errors.New("Failed to decode certificate. It should be PEM encoded.")
		certLogger.Error(err)
		return "", err
	}

	var certID string

	// Found private key, check if it match the certificate
	if len(keyPEM) > 0 {
		cert, err := tls.X509KeyPair(certChainPEM, keyPEM)
		if err != nil {
			certLogger.Error(err)
			return "", err
		}

		// Encrypt private key and append it to the chain
		encryptedKeyPEMBlock, err := x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", keyRaw, []byte(privateCertificateEncodingSecret()), x509.PEMCipherAES256)
		if err != nil {
			certLogger.Error("Failed to encode private key", err)
			return "", err
		}
		certChainPEM = append(certChainPEM, pem.EncodeToMemory(encryptedKeyPEMBlock)...)

		certID = certSHA256(cert.Certificate[0])
	} else {
		// Get first cert
		certRaw, _ := pem.Decode(certChainPEM)
		cert, err := x509.ParseCertificate(certRaw.Bytes)
		if err != nil {
			err := errors.New("Error while parsing certificate: " + err.Error())
			certLogger.Error(err)
			return "", err
		}

		certID = certSHA256(cert.Raw)
	}

	if err := redisCertificateStorage.SetKey("raw-"+certID, string(certChainPEM), 0); err != nil {
		certLogger.Error(err)
		return "", err
	}

	return certID, nil
}

func removeCertificate(certID string) {
	redisCertificateStorage.DeleteKey("raw-" + certID)
	certificateCache.Delete(certID)
}

func clientCertPool(certIDs []string) *x509.CertPool {
	pool := x509.NewCertPool()

	for _, cert := range fetchCertificates(certIDs, withoutPrivateKeys) {
		pool.AddCert(cert.Leaf)
	}

	return pool
}

func loadCertEndpoints(muxer *mux.Router) {
	certLevels := [...]struct {
		path string
		mode certificateListMode
	}{
		{"/", withoutPrivateKeys},
	}

	r := muxer.PathPrefix("/certs").Subrouter()

	for _, level := range certLevels {
		r.HandleFunc(level.path+"{_:/?}", certHandler(level.mode))
		r.HandleFunc(level.path+"/{certID}", certHandler(level.mode))
	}
}

func validateRequestCertificate(certIDs []string, r *http.Request) error {
	if r.TLS == nil {
		return errors.New("TLS not enabled")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return errors.New("Client TLS certificate is required")
	}

	leaf := r.TLS.PeerCertificates[0]

	certID := certSHA256(leaf.Raw)
	for _, cert := range fetchCertificates(certIDs, withoutPrivateKeys) {
		if string(cert.Leaf.Extensions[0].Value) == certID {
			return nil
		}
	}

	return errors.New("Certificate with SHA256 " + certID + " not allowed")
}

func certHandler(mode certificateListMode) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// apiID := mux.Vars(r)["apiID"]
		certID := mux.Vars(r)["certID"]
		query := r.URL.Path[len("/tyk/certs/"):]

		if certID != "" {
			// Strip certID
			query = query[:strings.LastIndex(query, "/")]
		}

		switch r.Method {
		case "POST", "PUT":
			content, err := ioutil.ReadAll(r.Body)
			if err != nil {
				doJSONWrite(w, 405, apiError("Malformed request body"))
				return
			}

			if _, err = addCertificate(content); err != nil {
				doJSONWrite(w, 403, apiError(err.Error()))
			}
		case "GET":
			if certID != "" {
				panic("not yet")
			} else {
				doJSONWrite(w, 200, nil)
			}
		case "DELETE":
			removeCertificate(certID)

			doJSONWrite(w, 200, &APIStatusMessage{"ok", "removed"})
		default:
			doJSONWrite(w, 405, apiError("Method not supported"))
		}
	}
}

func dummyGetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func getTLSConfigForClient(baseConfig *tls.Config, listenPort int) func(hello *tls.ClientHelloInfo) (*tls.Config, error) {

	// Supporting legacy certificate configuration
	certs := make([]tls.Certificate, 0)
	certNameMap := make(map[string]*tls.Certificate)
	for i, certData := range globalConf.HttpServerOptions.Certificates {
		cert, err := tls.LoadX509KeyPair(certData.CertFile, certData.KeyFile)
		if err != nil {
			certLogger.Fatalf("Server error: loadkeys: %s", err)
			continue
		}
		certs = append(certs, cert)
		certNameMap[certData.Name] = &certs[i]
	}

	for _, cert := range fetchCertificates(globalConf.HttpServerOptions.SSLCertificates, withPrivateKeys) {
		certs = append(certs, *cert)
	}

	baseConfig.Certificates = certs

	baseConfig.BuildNameToCertificate()
	for k, v := range certNameMap {
		baseConfig.NameToCertificate[k] = v
	}

	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		newConfig := baseConfig.Clone()

		isControlAPI := (listenPort != 0 && globalConf.ControlAPIPort == listenPort) || (globalConf.ControlAPIHostname == hello.ServerName)

		if isControlAPI && globalConf.Security.ControlAPIUseMutualTLS {
			newConfig.ClientAuth = tls.RequireAndVerifyClientCert
			newConfig.ClientCAs = clientCertPool(globalConf.Security.Certificates.ControlAPI)

			return newConfig, nil
		}

		for _, spec := range APISpecs {
			if spec.UseMutualTLSAuth && spec.Domain == hello.ServerName {
				newConfig.ClientAuth = tls.RequireAndVerifyClientCert
				newConfig.ClientCAs = clientCertPool(spec.ClientCertificates)
				break
			}
		}

		return newConfig, nil
	}
}
