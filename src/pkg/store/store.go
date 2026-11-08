package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store manages the on-disk cryptographic workspace and manifest.json inventory.
type Store struct {
	BaseDir string
	mu      sync.Mutex
}

// Manifest tracks all managed PKI, SSH, ACME, and Target artifacts in the store.
type Manifest struct {
	Version   string         `json:"version"`
	UpdatedAt time.Time      `json:"updated_at"`
	CAs       []CARecord     `json:"cas"`
	Certs     []CertRecord   `json:"certs"`
	SSHCAs    []SSHCARecord  `json:"ssh_cas"`
	SSHCerts  []SSHCertRecord `json:"ssh_certs"`
	ACMECerts []ACMERecord   `json:"acme_certs"`
	Targets   []TargetRecord `json:"targets"`
}

type CARecord struct {
	Name        string    `json:"name"`
	CommonName  string    `json:"common_name"`
	IsRoot      bool      `json:"is_root"`
	ParentCA    string    `json:"parent_ca,omitempty"`
	Algorithm   string    `json:"algorithm"`
	SerialHex   string    `json:"serial_hex"`
	CertPath    string    `json:"cert_path"`
	KeyPath     string    `json:"key_path"`
	ChainPath   string    `json:"chain_path"`
	CRLPath     string    `json:"crl_path,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
}

type CertRecord struct {
	Name          string    `json:"name"`
	CommonName    string    `json:"common_name"`
	CAName        string    `json:"ca_name,omitempty"`
	SelfSigned    bool      `json:"self_signed"`
	Role          string    `json:"role"` // server, client, mtls
	Algorithm     string    `json:"algorithm"`
	SerialHex     string    `json:"serial_hex"`
	DNSNames      []string  `json:"dns_names,omitempty"`
	IPAddresses   []string  `json:"ip_addresses,omitempty"`
	URIs          []string  `json:"uris,omitempty"`
	CertPath      string    `json:"cert_path"`
	KeyPath       string    `json:"key_path"`
	FullChainPath string    `json:"full_chain_path"`
	CAChainPath   string    `json:"ca_chain_path,omitempty"`
	DERPath       string    `json:"der_path,omitempty"`
	BundlePath    string    `json:"bundle_path,omitempty"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Revoked       bool      `json:"revoked"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	RevokeReason  int       `json:"revoke_reason,omitempty"`
	Fingerprint   string    `json:"fingerprint"`
	External      bool      `json:"external,omitempty"` // signed from an external CSR; mgtls does not hold the leaf private key
}

type SSHCARecord struct {
	Name        string    `json:"name"`
	CAType      string    `json:"ca_type"` // user, host
	Algorithm   string    `json:"algorithm"`
	PubKeyPath  string    `json:"pub_key_path"`
	PrivKeyPath string    `json:"priv_key_path"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

type SSHCertRecord struct {
	Name        string    `json:"name"`
	CAName      string    `json:"ca_name"`
	CertType    string    `json:"cert_type"` // user, host
	KeyID       string    `json:"key_id"`
	Serial      uint64    `json:"serial"`
	Principals  []string  `json:"principals"`
	CertPath    string    `json:"cert_path"`
	PubKeyPath  string    `json:"pub_key_path"`
	PrivKeyPath string    `json:"priv_key_path,omitempty"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

type ACMERecord struct {
	Name          string    `json:"name"`
	Provider      string    `json:"provider"`
	DirectoryURL  string    `json:"directory_url"`
	Email         string    `json:"email"`
	Domains       []string  `json:"domains"`
	ChallengeType string    `json:"challenge_type"`
	CertPath      string    `json:"cert_path"`
	KeyPath       string    `json:"key_path"`
	AccountKey    string    `json:"account_key_path"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
}

type TargetRecord struct {
	Name       string    `json:"name"`
	TargetType string    `json:"target_type"`
	OutputDir  string    `json:"output_dir"`
	CAName     string    `json:"ca_name"`
	ServerCert string    `json:"server_cert"`
	ClientCert string    `json:"client_cert,omitempty"`
	Files      []string  `json:"files"`
	CreatedAt  time.Time `json:"created_at"`
}

// New creates a Store instance rooted at baseDir.
func New(baseDir string) (*Store, error) {
	if baseDir == "" {
		baseDir = ".mgtls"
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve store dir: %w", err)
	}
	return &Store{BaseDir: abs}, nil
}

// Init creates the workspace directory tree and initializes manifest.json if absent.
func (s *Store) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dirs := []string{
		s.BaseDir,
		filepath.Join(s.BaseDir, "ca"),
		filepath.Join(s.BaseDir, "certs"),
		filepath.Join(s.BaseDir, "ssh"),
		filepath.Join(s.BaseDir, "acme"),
		filepath.Join(s.BaseDir, "targets"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	manifestPath := filepath.Join(s.BaseDir, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		m := &Manifest{
			Version:   "1.0",
			UpdatedAt: time.Now().UTC(),
			CAs:       []CARecord{},
			Certs:     []CertRecord{},
			SSHCAs:    []SSHCARecord{},
			SSHCerts:  []SSHCertRecord{},
			ACMECerts: []ACMERecord{},
			Targets:   []TargetRecord{},
		}
		return s.saveManifestLocked(m)
	}
	return nil
}

// Path resolves a relative path inside the store.
func (s *Store) Path(elem ...string) string {
	parts := append([]string{s.BaseDir}, elem...)
	return filepath.Join(parts...)
}

// SafePath resolves a relative path inside the store and verifies it does not escape BaseDir.
func (s *Store) SafePath(elem ...string) (string, error) {
	full := s.Path(elem...)
	rel, err := filepath.Rel(s.BaseDir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes store root %q", strings.Join(elem, "/"), s.BaseDir)
	}
	return full, nil
}

// WriteKey writes sensitive key material with strict 0600 permissions.
func (s *Store) WriteKey(relPath string, data []byte) (string, error) {
	full, err := s.SafePath(relPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		return "", fmt.Errorf("mkdir parent for key %s: %w", relPath, err)
	}
	if err := os.WriteFile(full, data, 0600); err != nil {
		return "", fmt.Errorf("write key %s: %w", relPath, err)
	}
	if err := os.Chmod(full, 0600); err != nil {
		return "", fmt.Errorf("chmod key %s: %w", relPath, err)
	}
	return full, nil
}

// WritePublic writes public certificates or configuration files with 0644 permissions.
func (s *Store) WritePublic(relPath string, data []byte) (string, error) {
	full, err := s.SafePath(relPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return "", fmt.Errorf("mkdir parent for public file %s: %w", relPath, err)
	}
	if err := os.WriteFile(full, data, 0644); err != nil {
		return "", fmt.Errorf("write public file %s: %w", relPath, err)
	}
	if err := os.Chmod(full, 0644); err != nil {
		return "", fmt.Errorf("chmod public file %s: %w", relPath, err)
	}
	return full, nil
}

// LoadManifest reads the current manifest from disk (initializing if needed).
func (s *Store) LoadManifest() (*Manifest, error) {
	if err := s.Init(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadManifestLocked()
}

func (s *Store) loadManifestLocked() (*Manifest, error) {
	manifestPath := filepath.Join(s.BaseDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return &m, nil
}

func (s *Store) saveManifestLocked(m *Manifest) error {
	m.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	tmpPath := filepath.Join(s.BaseDir, "manifest.json.tmp")
	finalPath := filepath.Join(s.BaseDir, "manifest.json")
	if err := os.WriteFile(tmpPath, raw, 0600); err != nil {
		return fmt.Errorf("write manifest tmp: %w", err)
	}
	return os.Rename(tmpPath, finalPath)
}

func (s *Store) UpsertCA(rec CARecord) error {
	if err := s.Init(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadManifestLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range m.CAs {
		if existing.Name == rec.Name {
			m.CAs[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		m.CAs = append(m.CAs, rec)
	}
	return s.saveManifestLocked(m)
}

func (s *Store) GetCA(name string) (*CARecord, error) {
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}
	for _, ca := range m.CAs {
		if ca.Name == name {
			cp := ca
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("CA %q not found in store", name)
}

func (s *Store) UpsertCert(rec CertRecord) error {
	if err := s.Init(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadManifestLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range m.Certs {
		if existing.Name == rec.Name {
			m.Certs[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		m.Certs = append(m.Certs, rec)
	}
	return s.saveManifestLocked(m)
}

func (s *Store) GetCert(name string) (*CertRecord, error) {
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}
	for _, c := range m.Certs {
		if c.Name == name {
			cp := c
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("certificate %q not found in store", name)
}

func (s *Store) UpsertSSHCA(rec SSHCARecord) error {
	if err := s.Init(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadManifestLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range m.SSHCAs {
		if existing.Name == rec.Name {
			m.SSHCAs[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		m.SSHCAs = append(m.SSHCAs, rec)
	}
	return s.saveManifestLocked(m)
}

func (s *Store) GetSSHCA(name string) (*SSHCARecord, error) {
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}
	for _, ca := range m.SSHCAs {
		if ca.Name == name {
			cp := ca
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("SSH CA %q not found in store", name)
}

func (s *Store) UpsertSSHCert(rec SSHCertRecord) error {
	if err := s.Init(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadManifestLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range m.SSHCerts {
		if existing.Name == rec.Name {
			m.SSHCerts[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		m.SSHCerts = append(m.SSHCerts, rec)
	}
	return s.saveManifestLocked(m)
}

func (s *Store) UpsertACME(rec ACMERecord) error {
	if err := s.Init(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadManifestLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range m.ACMECerts {
		if existing.Name == rec.Name {
			m.ACMECerts[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		m.ACMECerts = append(m.ACMECerts, rec)
	}
	return s.saveManifestLocked(m)
}

func (s *Store) UpsertTarget(rec TargetRecord) error {
	if err := s.Init(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadManifestLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range m.Targets {
		if existing.Name == rec.Name {
			m.Targets[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		m.Targets = append(m.Targets, rec)
	}
	return s.saveManifestLocked(m)
}
