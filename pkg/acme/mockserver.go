package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MockServer wraps an httptest.Server implementing an RFC 8555 ACME v2 CA for testing.
type MockServer struct {
	Server  *httptest.Server
	CACert  *x509.Certificate
	CAKey   *ecdsa.PrivateKey
	CAPEM   []byte
	mu      sync.Mutex
	counter int64
	orders  map[string]*acmeOrder
	authzs  map[string]*acmeAuthorization
	challs  map[string]string // challenge ID -> authz ID
	certs   map[string][]byte // cert ID -> PEM chain
	LastEAB map[string]any
}

// NewMockACMEServer starts an in-memory RFC 8555 ACME v2 server backed by a generated Root CA.
func NewMockACMEServer() *MockServer {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mock ACME Root CA", Organization: []string{"mgtls Test CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	ms := &MockServer{
		CACert: caCert,
		CAKey:  caKey,
		CAPEM:  caPEM,
		orders: make(map[string]*acmeOrder),
		authzs: make(map[string]*acmeAuthorization),
		challs: make(map[string]string),
		certs:  make(map[string][]byte),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", ms.handleDirectory)
	mux.HandleFunc("/new-nonce", ms.handleNewNonce)
	mux.HandleFunc("/new-account", ms.handleNewAccount)
	mux.HandleFunc("/new-order", ms.handleNewOrder)
	mux.HandleFunc("/order/", ms.handleOrder)
	mux.HandleFunc("/authz/", ms.handleAuthz)
	mux.HandleFunc("/chall/", ms.handleChallenge)
	mux.HandleFunc("/finalize/", ms.handleFinalize)
	mux.HandleFunc("/cert/", ms.handleCert)

	ms.Server = httptest.NewServer(mux)
	return ms
}

// DirectoryURL returns the ACME directory endpoint URL of the mock server.
func (m *MockServer) DirectoryURL() string {
	return m.Server.URL + "/directory"
}

// Close shuts down the underlying httptest.Server.
func (m *MockServer) Close() {
	m.Server.Close()
}

func (m *MockServer) nextNonce() string {
	id := atomic.AddInt64(&m.counter, 1)
	return fmt.Sprintf("mock-nonce-%d", id)
}

func (m *MockServer) setNonceHeader(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", m.nextNonce())
}

func (m *MockServer) decodeJWSPayload(r *http.Request) ([]byte, error) {
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return nil, err
	}
	if jws.Payload == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(jws.Payload)
}

func (m *MockServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(acmeDirectory{
		NewNonce:   m.Server.URL + "/new-nonce",
		NewAccount: m.Server.URL + "/new-account",
		NewOrder:   m.Server.URL + "/new-order",
	})
}

func (m *MockServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	w.WriteHeader(http.StatusNoContent)
}

func (m *MockServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	payload, err := m.decodeJWSPayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req map[string]any
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &req)
	}
	m.mu.Lock()
	if eab, ok := req["externalAccountBinding"].(map[string]any); ok {
		m.LastEAB = eab
	}
	m.mu.Unlock()

	w.Header().Set("Location", m.Server.URL+"/acct/1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "valid",
	})
}

func (m *MockServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	payload, err := m.decodeJWSPayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		Identifiers []acmeIdentifier `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	ordID := fmt.Sprintf("%d", atomic.AddInt64(&m.counter, 1))
	var authzURLs []string
	for _, ident := range req.Identifiers {
		aID := fmt.Sprintf("%d", atomic.AddInt64(&m.counter, 1))
		cHTTP := fmt.Sprintf("%d", atomic.AddInt64(&m.counter, 1))
		cALPN := fmt.Sprintf("%d", atomic.AddInt64(&m.counter, 1))
		cDNS := fmt.Sprintf("%d", atomic.AddInt64(&m.counter, 1))

		m.challs[cHTTP] = aID
		m.challs[cALPN] = aID
		m.challs[cDNS] = aID

		m.authzs[aID] = &acmeAuthorization{
			Identifier: ident,
			Status:     "pending",
			Challenges: []acmeChallenge{
				{
					Type:   "http-01",
					URL:    m.Server.URL + "/chall/" + cHTTP,
					Status: "pending",
					Token:  "token-http-" + aID,
				},
				{
					Type:   "tls-alpn-01",
					URL:    m.Server.URL + "/chall/" + cALPN,
					Status: "pending",
					Token:  "token-alpn-" + aID,
				},
				{
					Type:   "dns-01",
					URL:    m.Server.URL + "/chall/" + cDNS,
					Status: "pending",
					Token:  "token-dns-" + aID,
				},
			},
		}
		authzURLs = append(authzURLs, m.Server.URL+"/authz/"+aID)
	}

	ord := &acmeOrder{
		Status:         "pending",
		Identifiers:    req.Identifiers,
		Authorizations: authzURLs,
		Finalize:       m.Server.URL + "/finalize/" + ordID,
	}
	m.orders[ordID] = ord

	w.Header().Set("Location", m.Server.URL+"/order/"+ordID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ord)
}

func (m *MockServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	ordID := strings.TrimPrefix(r.URL.Path, "/order/")
	m.mu.Lock()
	ord, ok := m.orders[ordID]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ord)
}

func (m *MockServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	aID := strings.TrimPrefix(r.URL.Path, "/authz/")
	m.mu.Lock()
	authz, ok := m.authzs[aID]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authz)
}

func (m *MockServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	cID := strings.TrimPrefix(r.URL.Path, "/chall/")
	m.mu.Lock()
	aID, ok := m.challs[cID]
	var chalResp acmeChallenge
	if ok {
		if authz, exists := m.authzs[aID]; exists {
			authz.Status = "valid"
			for i := range authz.Challenges {
				if strings.HasSuffix(authz.Challenges[i].URL, "/"+cID) {
					authz.Challenges[i].Status = "valid"
					chalResp = authz.Challenges[i]
				}
			}
		}
	}
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(chalResp)
}

func (m *MockServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	ordID := strings.TrimPrefix(r.URL.Path, "/finalize/")
	payload, err := m.decodeJWSPayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	serial := big.NewInt(atomic.AddInt64(&m.counter, 1) + 1000)
	leafTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, m.CACert, csr.PublicKey, m.CAKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chainPEM := append(leafPEM, m.CAPEM...)

	m.mu.Lock()
	ord, ok := m.orders[ordID]
	if ok {
		m.certs[ordID] = chainPEM
		ord.Status = "valid"
		ord.Certificate = m.Server.URL + "/cert/" + ordID
	}
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Location", m.Server.URL+"/order/"+ordID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ord)
}

func (m *MockServer) handleCert(w http.ResponseWriter, r *http.Request) {
	m.setNonceHeader(w)
	ordID := strings.TrimPrefix(r.URL.Path, "/cert/")
	m.mu.Lock()
	pemBytes, ok := m.certs[ordID]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(pemBytes)
}
