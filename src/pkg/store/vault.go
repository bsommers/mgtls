package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Encrypted-at-rest private key vault (CAP-VAULT-001).
//
// When MGTLS_KEYFILE or MGTLS_PASSPHRASE is set, CA-class private keys that mgtls itself
// must read back (X.509 CA keys, SSH CA keys, ACME account keys) are written as an
// AES-256-GCM envelope inside a PEM block of type "MGTLS ENCRYPTED KEY". Leaf keys
// (server/client certificates) are deployment artifacts consumed by external software and
// are intentionally NOT encrypted. Reading transparently handles both sealed and plaintext
// files, so enabling the vault is non-breaking and `mgtls vault seal` migrates in place.

const (
	// EnvPassphrase holds a passphrase (scrypt-derived KEK).
	EnvPassphrase = "MGTLS_PASSPHRASE"
	// EnvKeyFile holds the path to a keyfile (>= 32 bytes; HKDF-derived KEK). Preferred over passphrase.
	EnvKeyFile = "MGTLS_KEYFILE"
	// EnvNewPassphrase / EnvNewKeyFile name the replacement credential for `vault rotate`.
	EnvNewPassphrase = "MGTLS_NEW_PASSPHRASE"
	EnvNewKeyFile    = "MGTLS_NEW_KEYFILE"

	// SealedPEMType is the PEM block type of an encrypted key envelope.
	SealedPEMType = "MGTLS ENCRYPTED KEY"

	vaultVersion   = "1"
	kdfScrypt      = "scrypt"
	kdfKeyfile     = "hkdf-sha256"
	scryptN        = 1 << 15
	scryptR        = 8
	scryptP        = 1
	minKeyFileSize = 32
	maxKeyFileSize = 1 << 20
	maxSealedBytes = 1 << 20
)

// Credential selects how the key-encryption key is derived. KeyFile wins if both are set.
type Credential struct {
	Passphrase string
	KeyFile    string
}

// Empty reports whether no credential is configured.
func (c Credential) Empty() bool { return c.Passphrase == "" && c.KeyFile == "" }

// CredentialFromEnv reads MGTLS_KEYFILE / MGTLS_PASSPHRASE.
func CredentialFromEnv() Credential {
	return Credential{Passphrase: os.Getenv(EnvPassphrase), KeyFile: os.Getenv(EnvKeyFile)}
}

// NewCredentialFromEnv reads MGTLS_NEW_KEYFILE / MGTLS_NEW_PASSPHRASE (for rotation).
func NewCredentialFromEnv() Credential {
	return Credential{Passphrase: os.Getenv(EnvNewPassphrase), KeyFile: os.Getenv(EnvNewKeyFile)}
}

func (c Credential) kind() string {
	if c.KeyFile != "" {
		return kdfKeyfile
	}
	return kdfScrypt
}

func (c Credential) deriveKey(kind string, salt []byte, n, r, p int) ([]byte, error) {
	switch kind {
	case kdfKeyfile:
		if c.KeyFile == "" {
			return nil, fmt.Errorf("key is sealed with a keyfile: set %s", EnvKeyFile)
		}
		info, err := os.Stat(c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read keyfile: %w", err)
		}
		if info.Size() > maxKeyFileSize {
			return nil, fmt.Errorf("keyfile %s too large (max %d bytes)", c.KeyFile, maxKeyFileSize)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("keyfile %s has insecure permissions %04o (expected 0600)", c.KeyFile, info.Mode().Perm())
		}
		raw, err := os.ReadFile(c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read keyfile: %w", err)
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) < minKeyFileSize {
			return nil, fmt.Errorf("keyfile %s too short: need at least %d bytes of key material", c.KeyFile, minKeyFileSize)
		}
		return hkdf.Key(sha256.New, raw, salt, "mgtls-vault-v1 aes-256-gcm", 32)
	case kdfScrypt:
		if c.Passphrase == "" {
			return nil, fmt.Errorf("key is sealed with a passphrase: set %s", EnvPassphrase)
		}
		return scrypt.Key([]byte(c.Passphrase), salt, n, r, p, 32)
	default:
		return nil, fmt.Errorf("unsupported vault KDF %q", kind)
	}
}

func sealedAAD(kdf, params string, salt []byte) []byte {
	return []byte("mgtls-vault-v" + vaultVersion + "|" + kdf + "|" + params + "|" + base64.StdEncoding.EncodeToString(salt))
}

// IsSealed reports whether data is an mgtls encrypted key envelope.
func IsSealed(data []byte) bool {
	b, _ := pem.Decode(data)
	return b != nil && b.Type == SealedPEMType
}

// Seal encrypts plaintext key material into a PEM envelope using AES-256-GCM.
func Seal(plain []byte, cred Credential) ([]byte, error) {
	if cred.Empty() {
		return nil, fmt.Errorf("no vault credential: set %s or %s", EnvKeyFile, EnvPassphrase)
	}
	kdf := cred.kind()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault salt: %w", err)
	}
	params := ""
	if kdf == kdfScrypt {
		params = fmt.Sprintf("N=%d,r=%d,p=%d", scryptN, scryptR, scryptP)
	}
	key, err := cred.deriveKey(kdf, salt, scryptN, scryptR, scryptP)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plain, sealedAAD(kdf, params, salt))
	headers := map[string]string{
		"Version": vaultVersion,
		"Cipher":  "AES-256-GCM",
		"KDF":     kdf,
		"Salt":    base64.StdEncoding.EncodeToString(salt),
	}
	if params != "" {
		headers["KDF-Params"] = params
	}
	return pem.EncodeToMemory(&pem.Block{Type: SealedPEMType, Headers: headers, Bytes: append(nonce, ct...)}), nil
}

// Open decrypts a PEM envelope produced by Seal. Plaintext (unsealed) input is returned as-is.
func Open(data []byte, cred Credential) ([]byte, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != SealedPEMType {
		return data, nil
	}
	if v := b.Headers["Version"]; v != vaultVersion {
		return nil, fmt.Errorf("unsupported vault envelope version %q", v)
	}
	if c := b.Headers["Cipher"]; c != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported vault cipher %q", c)
	}
	kdf := b.Headers["KDF"]
	salt, err := base64.StdEncoding.DecodeString(b.Headers["Salt"])
	if err != nil || len(salt) < 16 {
		return nil, errors.New("corrupt vault envelope: bad salt")
	}
	params := b.Headers["KDF-Params"]
	n, r, p := scryptN, scryptR, scryptP
	if kdf == kdfScrypt {
		if n, r, p, err = parseScryptParams(params); err != nil {
			return nil, err
		}
	}
	key, err := cred.deriveKey(kdf, salt, n, r, p)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(b.Bytes) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("corrupt vault envelope: truncated")
	}
	nonce, ct := b.Bytes[:gcm.NonceSize()], b.Bytes[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, sealedAAD(kdf, params, salt))
	if err != nil {
		return nil, errors.New("vault decryption failed: wrong passphrase/keyfile or tampered key file")
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// parseScryptParams enforces sane bounds so a tampered header cannot force huge allocations.
func parseScryptParams(s string) (n, r, p int, err error) {
	vals := map[string]int{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, 0, 0, fmt.Errorf("corrupt vault envelope: bad KDF-Params %q", s)
		}
		iv, e := strconv.Atoi(v)
		if e != nil {
			return 0, 0, 0, fmt.Errorf("corrupt vault envelope: bad KDF-Params %q", s)
		}
		vals[k] = iv
	}
	n, r, p = vals["N"], vals["r"], vals["p"]
	if n < 1<<14 || n > 1<<20 || n&(n-1) != 0 || r < 1 || r > 16 || p < 1 || p > 4 {
		return 0, 0, 0, fmt.Errorf("vault KDF-Params out of range: %q", s)
	}
	return n, r, p, nil
}

// WriteSecret writes CA-class key material: sealed when a vault credential is configured,
// otherwise identical to WriteKey (0600 plaintext).
func (s *Store) WriteSecret(relPath string, data []byte) (string, error) {
	cred := CredentialFromEnv()
	if cred.Empty() || IsSealed(data) {
		return s.WriteKey(relPath, data)
	}
	sealed, err := Seal(data, cred)
	if err != nil {
		return "", err
	}
	return s.WriteKey(relPath, sealed)
}

// ReadSecret reads a key file, transparently decrypting sealed envelopes using the
// environment credential.
func ReadSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !IsSealed(raw) {
		return raw, nil
	}
	plain, err := Open(raw, CredentialFromEnv())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return plain, nil
}

// VaultEntry describes one secret key file tracked in the manifest.
type VaultEntry struct {
	Kind   string `json:"kind"` // ca, ssh_ca, acme_account
	Name   string `json:"name"`
	Path   string `json:"path"`
	Sealed bool   `json:"sealed"`
	Status string `json:"status,omitempty"` // sealed, unsealed, missing, external, error:...
}

// VaultReport summarizes a vault operation.
type VaultReport struct {
	Enabled bool         `json:"credential_configured"`
	Entries []VaultEntry `json:"entries"`
	Changed int          `json:"changed"`
}

func (s *Store) secretPaths() ([]VaultEntry, error) {
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}
	var out []VaultEntry
	for _, ca := range m.CAs {
		if ca.KeyPath != "" {
			out = append(out, VaultEntry{Kind: "ca", Name: ca.Name, Path: ca.KeyPath})
		}
	}
	for _, ca := range m.SSHCAs {
		if ca.PrivKeyPath != "" {
			out = append(out, VaultEntry{Kind: "ssh_ca", Name: ca.Name, Path: ca.PrivKeyPath})
		}
	}
	for _, a := range m.ACMECerts {
		if a.AccountKey != "" {
			out = append(out, VaultEntry{Kind: "acme_account", Name: a.Name, Path: a.AccountKey})
		}
	}
	return out, nil
}

// VaultStatus reports which tracked secret keys are sealed.
func (s *Store) VaultStatus() (*VaultReport, error) {
	entries, err := s.secretPaths()
	if err != nil {
		return nil, err
	}
	rep := &VaultReport{Enabled: !CredentialFromEnv().Empty()}
	for _, e := range entries {
		raw, rerr := os.ReadFile(e.Path)
		switch {
		case rerr != nil:
			e.Status = "missing"
		case IsSealed(raw):
			e.Sealed, e.Status = true, "sealed"
		default:
			e.Status = "unsealed"
		}
		rep.Entries = append(rep.Entries, e)
	}
	return rep, nil
}

// transformSecrets rewrites every tracked secret key with fn (nil result = leave untouched).
func (s *Store) transformSecrets(fn func(raw []byte) ([]byte, error)) (*VaultReport, error) {
	entries, err := s.secretPaths()
	if err != nil {
		return nil, err
	}
	rep := &VaultReport{Enabled: !CredentialFromEnv().Empty()}
	type pending struct {
		e   VaultEntry
		out []byte
	}
	var todo []pending
	// Phase 1: compute all outputs first so a bad credential changes nothing.
	for _, e := range entries {
		info, serr := os.Lstat(e.Path)
		if serr != nil || !info.Mode().IsRegular() {
			e.Status = "missing"
			rep.Entries = append(rep.Entries, e)
			continue
		}
		if rel, rerr := filepath.Rel(s.BaseDir, e.Path); rerr != nil || strings.HasPrefix(rel, "..") {
			e.Status = "external"
			rep.Entries = append(rep.Entries, e)
			continue
		}
		raw, rerr := os.ReadFile(e.Path)
		if rerr != nil {
			return nil, fmt.Errorf("read %s: %w", e.Path, rerr)
		}
		out, ferr := fn(raw)
		if ferr != nil {
			return nil, fmt.Errorf("%s %q (%s): %w", e.Kind, e.Name, e.Path, ferr)
		}
		if out == nil {
			e.Sealed = IsSealed(raw)
			e.Status = map[bool]string{true: "sealed", false: "unsealed"}[e.Sealed]
			rep.Entries = append(rep.Entries, e)
			continue
		}
		todo = append(todo, pending{e, out})
	}
	// Phase 2: atomic replace.
	for _, p := range todo {
		if err := writeFileAtomic(p.e.Path, p.out, 0600); err != nil {
			return nil, err
		}
		p.e.Sealed = IsSealed(p.out)
		p.e.Status = map[bool]string{true: "sealed", false: "unsealed"}[p.e.Sealed]
		rep.Entries = append(rep.Entries, p.e)
		rep.Changed++
	}
	return rep, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SealAll encrypts every plaintext tracked secret key with the environment credential.
func (s *Store) SealAll() (*VaultReport, error) {
	cred := CredentialFromEnv()
	if cred.Empty() {
		return nil, fmt.Errorf("no vault credential: set %s or %s", EnvKeyFile, EnvPassphrase)
	}
	return s.transformSecrets(func(raw []byte) ([]byte, error) {
		if IsSealed(raw) {
			return nil, nil
		}
		return Seal(raw, cred)
	})
}

// UnsealAll decrypts every sealed tracked secret key back to plaintext using the environment credential.
func (s *Store) UnsealAll() (*VaultReport, error) {
	cred := CredentialFromEnv()
	return s.transformSecrets(func(raw []byte) ([]byte, error) {
		if !IsSealed(raw) {
			return nil, nil
		}
		return Open(raw, cred)
	})
}

// RotateAll re-encrypts every tracked secret key from the current credential to the
// MGTLS_NEW_* credential. Plaintext keys are sealed with the new credential.
func (s *Store) RotateAll() (*VaultReport, error) {
	oldCred, newCred := CredentialFromEnv(), NewCredentialFromEnv()
	if newCred.Empty() {
		return nil, fmt.Errorf("no new credential: set %s or %s", EnvNewKeyFile, EnvNewPassphrase)
	}
	return s.transformSecrets(func(raw []byte) ([]byte, error) {
		plain, err := Open(raw, oldCred)
		if err != nil {
			return nil, err
		}
		return Seal(plain, newCred)
	})
}
