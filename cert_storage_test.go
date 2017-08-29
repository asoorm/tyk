package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	_ "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
)

func flushCertificateStorage() {
	redisCertificateStorage.DeleteScanMatch("*")
}

func getTLSClient(cert *tls.Certificate, caCert []byte) *http.Client {
	// Setup HTTPS client
	tlsConfig := &tls.Config{}

	if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}

	return &http.Client{Transport: transport}
}

func genCertificate(template *x509.Certificate) ([]byte, []byte) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour)

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	var certPem, keyPem bytes.Buffer
	pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPem.Bytes(), keyPem.Bytes()
}

func genCertificateFromCommonName(cn string) ([]byte, []byte) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return genCertificate(tmpl)
}

func leafSubjectName(cert *tls.Certificate) string {
	x509сert, _ := x509.ParseCertificate(cert.Certificate[0])
	return x509сert.Subject.CommonName
}

// func TestAddCertificateTLS(t *testing.T) {
// 	defer flushCertificateStorage()

// 	certPem, keyPem := genCertificateFromCommonName("test")
// 	cert2Pem, key2Pem := genCertificateFromCommonName("test2")
// 	combinedPem := append(cert2Pem, key2Pem...)
// 	combinedPemWrongPrivate := append(cert2Pem, keyPem...)

// 	tests := [...]struct {
// 		data []byte
// 		err  string
// 	}{
// 		{[]byte(""), "Failed to decode certificate. It should be PEM encoded."},
// 		{[]byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----"), "Failed to decode certificate. It should be PEM encoded."},
// 		{[]byte("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"), "Error while parsing certificate: asn1: syntax error"},
// 		{certPem, ""},
// 		{combinedPemWrongPrivate, "tls: private key does not match public key"},
// 		{combinedPem, ""},
// 	}

// 	for _, tc := range tests {
// 		err := addCertificate("/", tc.data)
// 		if tc.err != "" {
// 			if err == nil {
// 				t.Error("Should error with", tc.err)
// 			} else {
// 				if !strings.HasPrefix(err.Error(), tc.err) {
// 					t.Error("Error not match", tc.err, "got:", err)
// 				}
// 			}
// 		} else {
// 			if err != nil {
// 				t.Error("Should not error", err)
// 			}
// 		}
// 	}
// }

// func TestCertificateStorageTLS(t *testing.T) {
// 	dir, _ := ioutil.TempDir("", "certs")

// 	defer func() {
// 		flushCertificateStorage()
// 		os.RemoveAll(dir)
// 	}()

// 	t.Run("File certificates", func(t *testing.T) {
// 		certPem, _ := genCertificateFromCommonName("file")

// 		os.MkdirAll(filepath.Join(dir, "apis"), 0755)
// 		certPath := filepath.Join(dir, "apis/cert.pem")
// 		ioutil.WriteFile(certPath, certPem, 0666)

// 		certs := listCertificates("/apis", withoutPrivateKeys)
// 		if len(certs) != 1 || leafSubjectName(certs[0]) != "file" {
// 			t.Error("Should contain 1 cert", len(certs))
// 		}

// 		if len(listCertificates("/apis", withoutPrivateKeys)) != 1 {
// 			t.Error("Global certificate should available to any node")
// 		}
// 	})

// 	t.Run("API certificates", func(t *testing.T) {
// 		globalApiCertPem, _ := genCertificateFromCommonName("redis")

// 		addCertificate("/apis", globalApiCertPem)

// 		certs := listCertificates("/apis/1", withoutPrivateKeys)

// 		if len(certs) != 2 {
// 			t.Fatal("Should contain 2 cert", len(certs))
// 		}

// 		if leafSubjectName(certs[0]) != "file" {
// 			t.Error("Wrong cert order", leafSubjectName(certs[0]))
// 		}

// 		if leafSubjectName(certs[1]) != "redis" {
// 			t.Error("Wrong cert order", leafSubjectName(certs[1]))
// 		}
// 	})
// }

func TestGatewayTLS(t *testing.T) {
	// Configure server
	serverCertPem, serverPrivPem := genCertificate(&x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
	})
	combinedPEM := bytes.Join([][]byte{serverCertPem, serverPrivPem}, []byte("\n"))

	globalConf.HttpServerOptions.UseSSL = true
	globalConf.ListenPort = 0

	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
		globalConf.HttpServerOptions.UseSSL = false
		globalConf.ListenPort = 8080
	}()

	t.Run("Without certificates", func(t *testing.T) {
		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)
		defer ln.Close()

		client := getTLSClient(nil, nil)
		_, err := client.Get(baseURL)

		if err == nil {
			t.Error("Should raise error without certificate")
		}
	})

	t.Run("Legacy TLS certificate path", func(t *testing.T) {
		certFilePath := filepath.Join(dir, "server.crt")
		ioutil.WriteFile(certFilePath, serverCertPem, 0666)

		certKeyPath := filepath.Join(dir, "server.key")
		ioutil.WriteFile(certKeyPath, serverPrivPem, 0666)

		globalConf.HttpServerOptions.Certificates = []config.CertData{{
			Name:     "localhost",
			CertFile: certFilePath,
			KeyFile:  certKeyPath,
		}}

		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)

		defer func() {
			ln.Close()
			os.Remove(certFilePath)
			os.Remove(certKeyPath)
			globalConf.HttpServerOptions.Certificates = []config.CertData{}
			certificateCache.Flush()
		}()

		client := getTLSClient(nil, nil)
		_, err := client.Get(baseURL)

		if err != nil {
			t.Error(err)
		}
	})

	t.Run("File certificate path", func(t *testing.T) {
		certPath := filepath.Join(dir, "server.pem")
		ioutil.WriteFile(certPath, combinedPEM, 0666)
		globalConf.HttpServerOptions.SSLCertificates = []string{certPath}

		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)

		defer func() {
			globalConf.HttpServerOptions.SSLCertificates = nil
			ln.Close()
			os.Remove(certPath)
			certificateCache.Flush()
		}()

		client := getTLSClient(nil, nil)
		_, err := client.Get(baseURL)

		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Redis certificate", func(t *testing.T) {
		defer flushCertificateStorage()

		certID, err := addCertificate(combinedPEM)
		if err != nil {
			t.Fatal(err)
		}

		globalConf.HttpServerOptions.SSLCertificates = []string{certID}

		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)

		defer func() {
			globalConf.HttpServerOptions.SSLCertificates = nil
			ln.Close()
			certificateCache.Flush()
		}()

		client := getTLSClient(nil, nil)

		if _, err := client.Get(baseURL); err != nil {
			t.Error(err)
		}
	})
}

func TestGatewayControlAPIMutualTLS(t *testing.T) {
	// Configure server
	serverCertPem, serverPrivPem := genCertificate(&x509.Certificate{
		DNSNames:    []string{"localhost", "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
	})
	combinedPEM := bytes.Join([][]byte{serverCertPem, serverPrivPem}, []byte("\n"))

	globalConf.HttpServerOptions.UseSSL = true
	globalConf.Security.ControlAPIUseMutualTLS = true
	globalConf.ListenPort = 0
	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
		flushCertificateStorage()
		globalConf.ControlAPIHostname = ""
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = false
		globalConf.ListenPort = 8080
	}()

	clientCertPem, clientPrivPem := genCertificate(&x509.Certificate{})
	clientCert, _ := tls.X509KeyPair(clientCertPem, clientPrivPem)
	clientWithCert := getTLSClient(&clientCert, serverCertPem)

	clientWithoutCert := getTLSClient(nil, nil)

	t.Run("Separate domain", func(t *testing.T) {
		certID, _ := addCertificate(combinedPEM)
		globalConf.ControlAPIHostname = "localhost"
		globalConf.HttpServerOptions.SSLCertificates = []string{certID}

		ln, _ := generateListener(0)
		baseControlAPIURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		baseURL := "https://" + ln.Addr().String()
		listen(ln, nil, nil)

		defer func(){
			ln.Close()
			flushCertificateStorage()
			globalConf.HttpServerOptions.SSLCertificates = nil
			globalConf.Security.Certificates.ControlAPI = nil
			removeCertificate(certSHA256(clientCertPem))
		}()

		if _, err := clientWithoutCert.Get(baseURL); err != nil {
			t.Error("Should acess tyk without client certificates", err)
		}

		if _, err := clientWithoutCert.Get(baseControlAPIURL); err == nil {
			t.Error("Should raise error for ControlAPI without certificate")
		}

		if _, err := clientWithCert.Get(baseControlAPIURL); err == nil {
			t.Error("Should raise error for for unknown certificate")
		}

		clientCertID, _ := addCertificate(clientCertPem)
		globalConf.Security.Certificates.ControlAPI = []string{clientCertID}

		if _, err := clientWithCert.Get(baseControlAPIURL); err != nil {
			t.Error("Should pass request with valid client cert", err)
		}
	})

	t.Run("Same domain", func(t *testing.T) {
		certID, _ := addCertificate(combinedPEM)
		globalConf.ControlAPIHostname = "localhost"
		globalConf.HttpServerOptions.SSLCertificates = []string{certID}

		certPath := filepath.Join(dir, "client.pem")
		ioutil.WriteFile(certPath, clientCertPem, 0666)

		ln, _ := generateListener(0)
		baseURL := "https://" + ln.Addr().String()
		listen(ln, nil, nil)
		loadAPIEndpoints(defaultRouter)
		loadAPIEndpoints(mainRouter)
		defer func(){
			ln.Close()
			globalConf.HttpServerOptions.SSLCertificates = nil
			globalConf.Security.Certificates.ControlAPI = nil
			flushCertificateStorage()
		}()

		if _, err := clientWithoutCert.Get(baseURL); err != nil {
			t.Error("Should acess tyk without client certificates", err)
		}

		req, _ := http.NewRequest("GET", baseURL+"/tyk/reload", nil)
		respJSON := struct {
			Message string `json:"message"`
		}{}

		if resp, err := clientWithoutCert.Do(withAuth(req)); err != nil {
			t.Error("Should not raise TLS without certificate", err)
		} else {
			json.NewDecoder(resp.Body).Decode(&respJSON)
			if respJSON.Message != `Client TLS certificate is required` {
				t.Error("Error not match:", respJSON.Message)
			}
		}

		if resp, err := clientWithCert.Do(withAuth(req)); err != nil {
			t.Error("Should not raise TLS for for unknown certificate", err)
		} else {
			json.NewDecoder(resp.Body).Decode(&respJSON)
			expectedErr := `Certificate with SHA256 ` + certSHA256(clientCert.Certificate[0]) + ` not allowed`

			if respJSON.Message != expectedErr {
				t.Error("Error not match:", respJSON.Message, expectedErr)
			}
		}

		clientCertID, _ := addCertificate(clientCertPem)
		globalConf.Security.Certificates.ControlAPI = []string{clientCertID}

		if resp, err := clientWithCert.Do(withAuth(req)); err != nil {
			t.Error("Should pass request with valid client cert", err)
		} else {
			if resp.StatusCode != 200 {
				t.Error("Should be valid requests")
			}
		}

		removeCertificate(clientCertID)

		globalConf.Security.Certificates.ControlAPI = []string{certPath}

		if resp, err := clientWithCert.Do(withAuth(req)); err != nil {
			t.Error("Should pass request with valid client cert", err)
		} else {
			if resp.StatusCode != 200 {
				t.Error("Should be valid requests")
			}
		}
	})
}

func TestAPIMutualTLS(t *testing.T) {
	// Configure server
	serverCertPem, serverPrivPem := genCertificate(&x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
	})
	combinedPEM := bytes.Join([][]byte{serverCertPem, serverPrivPem}, []byte("\n"))
	certID, _ := addCertificate(combinedPEM)

	globalConf.HttpServerOptions.UseSSL = true
	globalConf.ListenPort = 0
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}

	ln, err := generateListener(0)
	if err != nil {
		t.Fatal(err)
	}
	listen(ln, nil, nil)

	defer func() {
		ln.Close()
		globalConf.HttpServerOptions.SSLCertificates = nil
		globalConf.HttpServerOptions.UseSSL = false
		globalConf.ListenPort = 8080
	}()

	// Initialize client certificates
	clientCertPem, clientPrivPem := genCertificate(&x509.Certificate{})
	clientCert, _ := tls.X509KeyPair(clientCertPem, clientPrivPem)

	// Start of the tests
	// To make SSL SNI work we need to use domains
	baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)

	t.Run("SNI and domain per API", func(t *testing.T) {
		t.Run("API without mutual TLS", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
			})

			if resp, err := client.Get(baseURL); err != nil {
				t.Error("Should work as ordinary api", err)
			} else if resp.StatusCode != 200 {
				t.Error("Should load API", resp)
			}
		})

		t.Run("MutualTLSCertificate not set", func(t *testing.T) {
			client := getTLSClient(nil, nil)

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
			})

			if _, err := client.Get(baseURL); err == nil {
				t.Error("Should reject unknown certificate")
			}
		})

		t.Run("Client certificate match", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)
			clientCertID, _ := addCertificate(clientCertPem)

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID}
			})

			if resp, err := client.Get(baseURL); err != nil {
				t.Error("Mutual TLS should work", err)
			} else if resp.StatusCode != 200 {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Error("Should be valid request", resp, string(b))
			}

			removeCertificate(clientCertID)

			if _, err = client.Get(baseURL); err == nil {
				t.Error("Should error if certificate revoked")
			}
		})

		t.Run("Client certificate differ", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)

			clientCertPem2, _ := genCertificate(&x509.Certificate{})
			clientCertID2, _ := addCertificate(clientCertPem2)
			defer removeCertificate(clientCertID2)

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID2}
			})

			if _, err := client.Get(baseURL); err == nil {
				t.Error("Should reject wrong certificate")
			}
		})
	})

	t.Run("Multiple APIs on same domain", func(t *testing.T) {
		clientCertID, _ := addCertificate(clientCertPem)
		defer removeCertificate(clientCertID)

		loadAPIS := func(certs ...string) {
			buildAndLoadAPI(
				func(spec *APISpec) {
					spec.Proxy.ListenPath = "/with_mutual"
					spec.UseMutualTLSAuth = true
					spec.ClientCertificates = certs
				},
				func(spec *APISpec) {
					spec.Proxy.ListenPath = "/without_mutual"
				},
			)
		}

		respJSON := struct {
			Error string `json:"error"`
		}{}

		t.Run("Without certificate", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)
			clientWithoutCert := getTLSClient(nil, nil)

			loadAPIS()

			if resp, err := clientWithoutCert.Get(baseURL + "/with_mutual"); err != nil {
				t.Error("Should reject on HTTP level", err)
			} else {
				json.NewDecoder(resp.Body).Decode(&respJSON)

				if resp.StatusCode != 403 || respJSON.Error != `Client TLS certificate is required` {
					t.Error("Error not match:", respJSON.Error, resp.StatusCode)
				}
			}

			if resp, err := client.Get(baseURL + "/without_mutual"); err != nil {
				t.Error("Should not error", err)
			} else if resp.StatusCode != 200 {
				t.Error("Should process request", resp.StatusCode)
			}
		})

		t.Run("Client certificate not match", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)

			loadAPIS()

			if resp, err := client.Get(baseURL + "/with_mutual"); err != nil {
				t.Error("Should reject on HTTP level", err)
			} else {
				expectedErr := `Certificate with SHA256 ` + certSHA256(clientCert.Certificate[0]) + ` not allowed`
				json.NewDecoder(resp.Body).Decode(&respJSON)

				if resp.StatusCode != 403 || respJSON.Error != expectedErr {
					t.Error("Error not match:", respJSON.Error, expectedErr, resp.StatusCode)
				}
			}
		})

		t.Run("Client certificate match", func(t *testing.T) {
			loadAPIS(clientCertID)

			client := getTLSClient(&clientCert, serverCertPem)

			if resp, err := client.Get(baseURL + "/with_mutual"); err != nil {
				t.Error("Should reject on HTTP level", err)
			} else {
				if resp.StatusCode != 200 {
					t.Error("Error not match:", resp.StatusCode)
				}
			}
		})
	})
}

func TestUpstreamMutualTLS(t *testing.T) {
	clientCertPem, clientPrivPem := genCertificate(&x509.Certificate{})
	clientCert, _ := tls.X509KeyPair(clientCertPem, clientPrivPem)
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	pool := x509.NewCertPool()
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool,
		InsecureSkipVerify: true,
	}
	ts.StartTLS()
	defer ts.Close()

	t.Run("Without API", func(t *testing.T){
		client := getTLSClient(&clientCert, nil)

		if _, err := client.Get(ts.URL); err == nil {
			t.Error("Should reject without certificate")
		}

		pool.AddCert(clientCert.Leaf)

		if _, err := client.Get(ts.URL); err != nil {
			t.Error("Should pass with valid certificate")
		}
	})

	t.Run("Upstream API", func(t *testing.T){
		combinedClientPEM := bytes.Join([][]byte{clientCertPem, clientPrivPem}, []byte("\n"))
		clientCertID, _ := addCertificate(combinedClientPEM)
		defer removeCertificate(clientCertID)

		pool.AddCert(clientCert.Leaf)

		ln, _ := generateListener(0)
		baseURL := "http://" + ln.Addr().String()
		listen(ln, nil, nil)
		globalConf.ProxySSLInsecureSkipVerify = true
		defer func(){
			ln.Close()
			globalConf.ProxySSLInsecureSkipVerify = false
		}()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = ts.URL
			spec.UpstreamCertificates = map[string]string{
				"*": clientCertID,
			}
		})

		client := getTLSClient(nil, nil)

		if resp, _ := client.Get(baseURL); resp.StatusCode != 200 {
			t.Error("Should pass pass request with valid upstream certificate", resp)
		}
	})
}