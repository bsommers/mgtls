package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/pkg/store"
)

// ProviderInfo describes a built-in or custom ACME v2 Certificate Authority.
type ProviderInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DirectoryURL string `json:"directory_url"`
	RequiresEAB  bool   `json:"requires_eab"`
	Free         bool   `json:"free"`
	Description  string `json:"description"`
}

// ObtainRequest specifies parameters for obtaining or renewing an ACME certificate.
type ObtainRequest struct {
	Name          string   `json:"name" yaml:"name"`
	Provider      string   `json:"provider" yaml:"provider"` // letsencrypt, letsencrypt-staging, zerossl, buypass, google, custom
	DirectoryURL  string   `json:"directory_url,omitempty" yaml:"directory_url,omitempty"`
	Email         string   `json:"email" yaml:"email"`
	Domains       []string `json:"domains" yaml:"domains"`
	ChallengeType string   `json:"challenge_type,omitempty" yaml:"challenge_type,omitempty"` // http-01 (default), tls-alpn-01, dns-01
	HTTPPort      int      `json:"http_port,omitempty" yaml:"http_port,omitempty"`           // optional local port for http-01/tls-alpn-01 solver
	WebrootDir    string   `json:"webroot_dir,omitempty" yaml:"webroot_dir,omitempty"`       // optional webroot for http-01
	DNSExecHook   string   `json:"dns_exec_hook,omitempty" yaml:"dns_exec_hook,omitempty"`   // optional shell hook for dns-01
	EABKID        string   `json:"eab_kid,omitempty" yaml:"eab_kid,omitempty"`
	EABHMACKey    string   `json:"eab_hmac_key,omitempty" yaml:"eab_hmac_key,omitempty"`     // base64url HMAC key
	SkipVerifyTLS bool     `json:"skip_verify_tls,omitempty" yaml:"skip_verify_tls,omitempty"` // for local test ACME servers
}

// ObtainResult holds the persisted ACMERecord and any computed DNS TXT records.
type ObtainResult struct {
	Record       store.ACMERecord  `json:"record"`
	DNSTXTRecord map[string]string `json:"dns_txt_records,omitempty"` // domain -> _acme-challenge TXT value
}

var builtinProviders = []ProviderInfo{
	{
		ID:           "letsencrypt",
		Name:         "Let's Encrypt (Production)",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		RequiresEAB:  false,
		Free:         true,
		Description:  "ISRG free automated Certificate Authority (90-day DV certificates)",
	},
	{
		ID:           "letsencrypt-staging",
		Name:         "Let's Encrypt (Staging)",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		RequiresEAB:  false,
		Free:         true,
		Description:  "Let's Encrypt staging environment with higher rate limits for testing",
	},
	{
		ID:           "zerossl",
		Name:         "ZeroSSL",
		DirectoryURL: "https://acme.zerossl.com/v2/DV90",
		RequiresEAB:  true,
		Free:         true,
		Description:  "ZeroSSL ACME v2 CA (supports free tier with EAB credentials)",
	},
	{
		ID:           "buypass",
		Name:         "Buypass Go SSL",
		DirectoryURL: "https://api.buypass.com/acme/directory",
		RequiresEAB:  false,
		Free:         true,
		Description:  "European CA offering free 180-day ACME DV certificates",
	},
	{
		ID:           "google",
		Name:         "Google Trust Services",
		DirectoryURL: "https://dv.acme-v02.api.pki.goog/directory",
		RequiresEAB:  true,
		Free:         true,
		Description:  "Google Public CA ACME v2 endpoint (requires GCP EAB key)",
	},
}

// ListProviders returns all built-in ACME providers.
func ListProviders() []ProviderInfo {
	out := make([]ProviderInfo, len(builtinProviders))
	copy(out, builtinProviders)
	return out
}

// ResolveProvider resolves a built-in provider ID or a custom ACME directory URL.
func ResolveProvider(idOrURL string) (ProviderInfo, error) {
	id := strings.ToLower(strings.TrimSpace(idOrURL))
	if id == "" {
		id = "letsencrypt"
	}
	for _, p := range builtinProviders {
		if p.ID == id {
			return p, nil
		}
	}
	if strings.HasPrefix(idOrURL, "https://") || strings.HasPrefix(idOrURL, "http://") {
		return ProviderInfo{
			ID:           "custom",
			Name:         "Custom ACME v2 CA",
			DirectoryURL: idOrURL,
			RequiresEAB:  false,
			Free:         true,
			Description:  "Custom RFC 8555 ACME v2 directory endpoint",
		}, nil
	}
	return ProviderInfo{}, fmt.Errorf("unknown ACME provider %q", idOrURL)
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type acmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeOrder struct {
	Status         string           `json:"status"`
	Expires        string           `json:"expires,omitempty"`
	Identifiers    []acmeIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate,omitempty"`
}

type acmeAuthorization struct {
	Identifier acmeIdentifier  `json:"identifier"`
	Status     string          `json:"status"`
	Challenges []acmeChallenge `json:"challenges"`
}

type acmeChallenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Token  string `json:"token"`
}

// ObtainCertificate executes the RFC 8555 ACME v2 workflow to obtain a signed certificate.
func ObtainCertificate(ctx context.Context, s *store.Store, req ObtainRequest) (*ObtainResult, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("ACME request name is required")
	}
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	if req.ChallengeType == "" {
		req.ChallengeType = "http-01"
	}
	switch req.ChallengeType {
	case "http-01", "tls-alpn-01", "dns-01":
	default:
		return nil, fmt.Errorf("unsupported ACME challenge type %q", req.ChallengeType)
	}

	var prov ProviderInfo
	var err error
	if req.DirectoryURL != "" && (req.Provider == "" || req.Provider == "custom") {
		prov, err = ResolveProvider(req.DirectoryURL)
	} else {
		prov, err = ResolveProvider(req.Provider)
		if err == nil && req.DirectoryURL != "" {
			prov.DirectoryURL = req.DirectoryURL
		}
	}
	if err != nil {
		return nil, err
	}
	if prov.RequiresEAB && (req.EABKID == "" || req.EABHMACKey == "") {
		return nil, fmt.Errorf("provider %q requires EAB credentials (eab_kid and eab_hmac_key)", prov.ID)
	}

	if err := s.Init(); err != nil {
		return nil, err
	}

	acctKey, acctKeyPath, err := loadOrCreateAccountKey(s, req.Name)
	if err != nil {
		return nil, err
	}
	jwkMap, thumbprint, err := computeJWKAndThumbprint(&acctKey.PublicKey)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: req.SkipVerifyTLS, //nolint:gosec
			MinVersion:         tls.VersionTLS12,
		},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	client := &acmeClient{
		http:       httpClient,
		acctKey:    acctKey,
		jwk:        jwkMap,
		thumbprint: thumbprint,
	}

	if err := client.fetchDirectory(ctx, prov.DirectoryURL); err != nil {
		return nil, err
	}
	if err := client.registerAccount(ctx, req.Email, req.EABKID, req.EABHMACKey); err != nil {
		return nil, err
	}

	order, orderURL, err := client.createOrder(ctx, req.Domains)
	if err != nil {
		return nil, err
	}

	dnsRecords := make(map[string]string)

	for _, authzURL := range order.Authorizations {
		authz, err := client.getAuthorization(ctx, authzURL)
		if err != nil {
			return nil, err
		}
		if authz.Status == "valid" {
			continue
		}

		var selected *acmeChallenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == req.ChallengeType {
				selected = &authz.Challenges[i]
				break
			}
		}
		if selected == nil {
			return nil, fmt.Errorf("challenge type %q not offered for domain %q", req.ChallengeType, authz.Identifier.Value)
		}

		keyAuth := selected.Token + "." + client.thumbprint
		domain := authz.Identifier.Value

		cleanup := func() {}
		switch req.ChallengeType {
		case "http-01":
			cleanup, err = setupHTTP01Solver(req, selected.Token, keyAuth)
			if err != nil {
				return nil, err
			}

		case "tls-alpn-01":
			cleanup, err = setupTLSALPN01Solver(req, domain, keyAuth)
			if err != nil {
				return nil, err
			}

		case "dns-01":
			sum := sha256.Sum256([]byte(keyAuth))
			txtVal := base64.RawURLEncoding.EncodeToString(sum[:])
			dnsRecords["_acme-challenge."+domain] = txtVal
			if req.DNSExecHook != "" {
				cmd := exec.CommandContext(ctx, "sh", "-c", req.DNSExecHook)
				cmd.Env = append(os.Environ(),
					"ACME_DOMAIN="+domain,
					"ACME_TOKEN="+selected.Token,
					"ACME_KEY_AUTH="+keyAuth,
					"ACME_TXT_NAME=_acme-challenge."+domain,
					"ACME_TXT_VALUE="+txtVal,
				)
				if out, err := cmd.CombinedOutput(); err != nil {
					return nil, fmt.Errorf("dns_exec_hook failed: %w (%s)", err, strings.TrimSpace(string(out)))
				}
			}
		}

		if err := client.triggerChallenge(ctx, selected.URL); err != nil {
			cleanup()
			return nil, err
		}
		if err := client.waitAuthorization(ctx, authzURL); err != nil {
			cleanup()
			return nil, err
		}
		cleanup()
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	csrDER, err := createCSR(leafKey, req.Domains)
	if err != nil {
		return nil, err
	}

	finalOrder, err := client.finalizeOrder(ctx, order.Finalize, orderURL, csrDER)
	if err != nil {
		return nil, err
	}

	certPEM, err := client.downloadCertificate(ctx, finalOrder.Certificate)
	if err != nil {
		return nil, err
	}

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})

	certPath, err := s.WritePublic(filepath.Join("acme", req.Name, "cert.pem"), certPEM)
	if err != nil {
		return nil, err
	}
	keyPath, err := s.WriteKey(filepath.Join("acme", req.Name, "key.pem"), leafKeyPEM)
	if err != nil {
		return nil, err
	}

	notBefore, notAfter := parseCertValidity(certPEM)
	rec := store.ACMERecord{
		Name:          req.Name,
		Provider:      prov.ID,
		DirectoryURL:  prov.DirectoryURL,
		Email:         req.Email,
		Domains:       req.Domains,
		ChallengeType: req.ChallengeType,
		CertPath:      certPath,
		KeyPath:       keyPath,
		AccountKey:    acctKeyPath,
		NotBefore:     notBefore,
		NotAfter:      notAfter,
	}
	if err := s.UpsertACME(rec); err != nil {
		return nil, err
	}

	return &ObtainResult{
		Record:       rec,
		DNSTXTRecord: dnsRecords,
	}, nil
}

// CheckRenewal returns ACME records expiring within thresholdDays (default 30).
func CheckRenewal(s *store.Store, thresholdDays int) ([]store.ACMERecord, error) {
	if thresholdDays <= 0 {
		thresholdDays = 30
	}
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().Add(time.Duration(thresholdDays) * 24 * time.Hour)
	var due []store.ACMERecord
	for _, rec := range m.ACMECerts {
		if rec.NotAfter.Before(cutoff) {
			due = append(due, rec)
		}
	}
	return due, nil
}

// oidACMEIdentifier is the RFC 8737 id-pe-acmeIdentifier OID (1.3.6.1.5.5.7.1.31).
var oidACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// BuildTLSALPN01Cert generates a self-signed certificate for the RFC 8737 tls-alpn-01 challenge.
func BuildTLSALPN01Cert(domain, keyAuth string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	extVal, err := asn1.Marshal(sum[:])
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidACMEIdentifier,
				Critical: true,
				Value:    extVal,
			},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func setupHTTP01Solver(req ObtainRequest, token, keyAuth string) (func(), error) {
	var cleanups []func()
	if req.WebrootDir != "" {
		chalDir := filepath.Join(req.WebrootDir, ".well-known", "acme-challenge")
		if err := os.MkdirAll(chalDir, 0755); err != nil {
			return func() {}, fmt.Errorf("mkdir webroot challenge dir: %w", err)
		}
		chalFile := filepath.Join(chalDir, token)
		if err := os.WriteFile(chalFile, []byte(keyAuth), 0644); err != nil {
			return func() {}, fmt.Errorf("write webroot challenge file: %w", err)
		}
		cleanups = append(cleanups, func() { _ = os.Remove(chalFile) })
	}

	if req.HTTPPort > 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/acme-challenge/"+token, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(keyAuth))
		})
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", req.HTTPPort))
		if err != nil {
			for _, fn := range cleanups {
				fn()
			}
			return func() {}, fmt.Errorf("listen http-01 port %d: %w", req.HTTPPort, err)
		}
		srv := &http.Server{Handler: mux}
		go func() { _ = srv.Serve(ln) }()
		cleanups = append(cleanups, func() { _ = srv.Close() })
	}

	return func() {
		for _, fn := range cleanups {
			fn()
		}
	}, nil
}

func setupTLSALPN01Solver(req ObtainRequest, domain, keyAuth string) (func(), error) {
	tlsCert, err := BuildTLSALPN01Cert(domain, keyAuth)
	if err != nil {
		return func() {}, err
	}
	if req.HTTPPort <= 0 {
		return func() {}, nil
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"acme-tls/1"},
		Certificates: []tls.Certificate{tlsCert},
	}
	ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", req.HTTPPort), tlsCfg)
	if err != nil {
		return func() {}, fmt.Errorf("listen tls-alpn-01 port %d: %w", req.HTTPPort, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	return func() { _ = ln.Close() }, nil
}

type acmeClient struct {
	http       *http.Client
	acctKey    *ecdsa.PrivateKey
	jwk        map[string]string
	thumbprint string
	dir        acmeDirectory
	kid        string
	nonce      string
}

func (c *acmeClient) fetchDirectory(ctx context.Context, dirURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dirURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch ACME directory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch ACME directory HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(&c.dir)
}

func (c *acmeClient) getNonce(ctx context.Context) (string, error) {
	if c.nonce != "" {
		n := c.nonce
		c.nonce = ""
		return n, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch nonce: %w", err)
	}
	defer resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", fmt.Errorf("empty Replay-Nonce header from ACME server")
	}
	return n, nil
}

func (c *acmeClient) signJWS(ctx context.Context, url string, payload any, useJWK bool) ([]byte, error) {
	nonce, err := c.getNonce(ctx)
	if err != nil {
		return nil, err
	}
	hdr := map[string]any{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}
	if useJWK {
		hdr["jwk"] = c.jwk
	} else {
		hdr["kid"] = c.kid
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	var payloadB64 string
	if payload != nil {
		pJSON, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadB64 = base64.RawURLEncoding.EncodeToString(pJSON)
	}

	signingInput := protectedB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.acctKey, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	jws := map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": sigB64,
	}
	return json.Marshal(jws)
}

func (c *acmeClient) postJWS(ctx context.Context, url string, payload any, useJWK bool) (*http.Response, []byte, error) {
	body, err := c.signJWS(ctx, url, payload, useJWK)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	if resp.StatusCode >= 400 {
		return resp, respBytes, fmt.Errorf("ACME request %s failed HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	return resp, respBytes, nil
}

func (c *acmeClient) registerAccount(ctx context.Context, email, eabKID, eabHMACKey string) error {
	payload := map[string]any{
		"termsOfServiceAgreed": true,
	}
	if email != "" {
		payload["contact"] = []string{"mailto:" + email}
	}
	if eabKID != "" && eabHMACKey != "" {
		eab, err := buildEABJWS(c.jwk, eabKID, eabHMACKey, c.dir.NewAccount)
		if err != nil {
			return err
		}
		payload["externalAccountBinding"] = eab
	}
	resp, _, err := c.postJWS(ctx, c.dir.NewAccount, payload, true)
	if err != nil {
		return fmt.Errorf("register account: %w", err)
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		return fmt.Errorf("ACME newAccount response missing Location header")
	}
	return nil
}

func buildEABJWS(jwk map[string]string, kid, hmacKeyB64, url string) (map[string]string, error) {
	macKey, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(hmacKeyB64, "="))
	if err != nil {
		return nil, fmt.Errorf("decode EAB HMAC key: %w", err)
	}
	hdr := map[string]string{
		"alg": "HS256",
		"kid": kid,
		"url": url,
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(jwkJSON)
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(protectedB64 + "." + payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": sigB64,
	}, nil
}

func (c *acmeClient) createOrder(ctx context.Context, domains []string) (*acmeOrder, string, error) {
	ids := make([]acmeIdentifier, len(domains))
	for i, d := range domains {
		ids[i] = acmeIdentifier{Type: "dns", Value: d}
	}
	payload := map[string]any{"identifiers": ids}
	resp, body, err := c.postJWS(ctx, c.dir.NewOrder, payload, false)
	if err != nil {
		return nil, "", fmt.Errorf("create order: %w", err)
	}
	var ord acmeOrder
	if err := json.Unmarshal(body, &ord); err != nil {
		return nil, "", err
	}
	return &ord, resp.Header.Get("Location"), nil
}

func (c *acmeClient) getAuthorization(ctx context.Context, authzURL string) (*acmeAuthorization, error) {
	_, body, err := c.postJWS(ctx, authzURL, nil, false)
	if err != nil {
		return nil, fmt.Errorf("get authorization: %w", err)
	}
	var authz acmeAuthorization
	if err := json.Unmarshal(body, &authz); err != nil {
		return nil, err
	}
	return &authz, nil
}

func (c *acmeClient) triggerChallenge(ctx context.Context, chalURL string) error {
	_, _, err := c.postJWS(ctx, chalURL, map[string]any{}, false)
	return err
}

func (c *acmeClient) waitAuthorization(ctx context.Context, authzURL string) error {
	for i := 0; i < 30; i++ {
		authz, err := c.getAuthorization(ctx, authzURL)
		if err != nil {
			return err
		}
		switch authz.Status {
		case "valid":
			return nil
		case "invalid":
			return fmt.Errorf("authorization %s became invalid", authzURL)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("timeout waiting for authorization %s", authzURL)
}

func (c *acmeClient) finalizeOrder(ctx context.Context, finalizeURL, orderURL string, csrDER []byte) (*acmeOrder, error) {
	payload := map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}
	_, body, err := c.postJWS(ctx, finalizeURL, payload, false)
	if err != nil {
		return nil, fmt.Errorf("finalize order: %w", err)
	}
	var ord acmeOrder
	if err := json.Unmarshal(body, &ord); err != nil {
		return nil, err
	}
	if ord.Status == "valid" && ord.Certificate != "" {
		return &ord, nil
	}
	if orderURL == "" {
		return nil, fmt.Errorf("order not immediately valid and order Location URL missing")
	}
	for i := 0; i < 30; i++ {
		_, pollBody, err := c.postJWS(ctx, orderURL, nil, false)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(pollBody, &ord); err != nil {
			return nil, err
		}
		if ord.Status == "valid" && ord.Certificate != "" {
			return &ord, nil
		}
		if ord.Status == "invalid" {
			return nil, fmt.Errorf("order %s became invalid", orderURL)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("timeout polling order %s", orderURL)
}

func (c *acmeClient) downloadCertificate(ctx context.Context, certURL string) ([]byte, error) {
	_, body, err := c.postJWS(ctx, certURL, nil, false)
	if err != nil {
		return nil, fmt.Errorf("download certificate: %w", err)
	}
	return body, nil
}

func loadOrCreateAccountKey(s *store.Store, name string) (*ecdsa.PrivateKey, string, error) {
	rel := filepath.Join("acme", name, "account-key.pem")
	full := s.Path(rel)
	if raw, err := os.ReadFile(full); err == nil {
		block, _ := pem.Decode(raw)
		if block != nil {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				return key, full, nil
			}
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	path, err := s.WriteKey(rel, pemBytes)
	if err != nil {
		return nil, "", err
	}
	return priv, path, nil
}

func computeJWKAndThumbprint(pub *ecdsa.PublicKey) (map[string]string, string, error) {
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	copy(xBytes[32-len(xb):], xb)
	copy(yBytes[32-len(yb):], yb)

	xB64 := base64.RawURLEncoding.EncodeToString(xBytes)
	yB64 := base64.RawURLEncoding.EncodeToString(yBytes)

	jwk := map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   xB64,
		"y":   yB64,
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, xB64, yB64)
	sum := sha256.Sum256([]byte(canonical))
	return jwk, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func createCSR(priv *ecdsa.PrivateKey, domains []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
}

func parseCertValidity(certPEM []byte) (time.Time, time.Time) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Now().UTC(), time.Now().UTC().Add(90 * 24 * time.Hour)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Now().UTC(), time.Now().UTC().Add(90 * 24 * time.Hour)
	}
	return cert.NotBefore.UTC(), cert.NotAfter.UTC()
}
