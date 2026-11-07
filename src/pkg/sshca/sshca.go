package sshca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
)

type SSHCARequest struct {
	Name      string     `json:"name" yaml:"name"`
	CAType    string     `json:"ca_type" yaml:"ca_type"`                         // "user" or "host"
	Algorithm string     `json:"algorithm,omitempty" yaml:"algorithm,omitempty"` // "ed25519" (default), "ecdsa-p256", "rsa-4096"
	Comment   string     `json:"comment,omitempty" yaml:"comment,omitempty"`
	Signer    ssh.Signer `json:"-" yaml:"-"` // optional hardware/agent/KMS signer (private key never written to disk)
}

type SSHCAResult struct {
	Record store.SSHCARecord `json:"record"`
}

type SignSSHRequest struct {
	Name            string            `json:"name" yaml:"name"`
	CAName          string            `json:"ca_name" yaml:"ca_name"`
	CertType        string            `json:"cert_type,omitempty" yaml:"cert_type,omitempty"` // "user" or "host" (inferred from CA if empty)
	KeyID           string            `json:"key_id" yaml:"key_id"`
	Principals      []string          `json:"principals" yaml:"principals"`
	ValidHours      int               `json:"valid_hours,omitempty" yaml:"valid_hours,omitempty"`           // default 720 (30d) for user, 8760 (365d) for host
	Algorithm       string            `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`               // used if generating new keypair
	ExistingPubKey  string            `json:"existing_pub_key,omitempty" yaml:"existing_pub_key,omitempty"` // optional path to existing .pub
	CriticalOptions map[string]string `json:"critical_options,omitempty" yaml:"critical_options,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty" yaml:"extensions,omitempty"`
	CASigner        ssh.Signer        `json:"-" yaml:"-"`                                           // optional hardware/agent/KMS CA signer
	AgentSocket     string            `json:"agent_socket,omitempty" yaml:"agent_socket,omitempty"` // optional SSH_AUTH_SOCK path for hardware/agent CA signing
}

type SignSSHResult struct {
	Record store.SSHCertRecord `json:"record"`
}

type SSHCertInfo struct {
	KeyID           string            `json:"key_id"`
	Serial          uint64            `json:"serial"`
	CertType        string            `json:"cert_type"` // "user" or "host"
	Principals      []string          `json:"principals"`
	ValidAfter      time.Time         `json:"valid_after"`
	ValidBefore     time.Time         `json:"valid_before"`
	CAFingerprint   string            `json:"ca_fingerprint"`
	KeyFingerprint  string            `json:"key_fingerprint"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
}

type SSHConfigRequest struct {
	Name         string   `json:"name" yaml:"name"`
	UserCAName   string   `json:"user_ca_name,omitempty" yaml:"user_ca_name,omitempty"`
	HostCAName   string   `json:"host_ca_name,omitempty" yaml:"host_ca_name,omitempty"`
	HostCertName string   `json:"host_cert_name,omitempty" yaml:"host_cert_name,omitempty"`
	UserCertName string   `json:"user_cert_name,omitempty" yaml:"user_cert_name,omitempty"`
	HostPatterns []string `json:"host_patterns,omitempty" yaml:"host_patterns,omitempty"` // e.g. ["*.internal", "10.0.0.*"]
	Principals   []string `json:"principals,omitempty" yaml:"principals,omitempty"`
	OutputDir    string   `json:"output_dir,omitempty" yaml:"output_dir,omitempty"`
}

type SSHConfigBundle struct {
	OutputDir            string            `json:"output_dir"`
	SSHDConfigPath       string            `json:"sshd_config_path"`
	SSHClientConfigPath  string            `json:"ssh_client_config_path"`
	KnownHostsPath       string            `json:"known_hosts_path"`
	AuthorizedPrincipals string            `json:"authorized_principals_path"`
	Files                map[string]string `json:"files"`
}

func generateSSHKeyPair(alg, comment string) (crypto.PrivateKey, ssh.PublicKey, []byte, []byte, string, error) {
	normAlg := strings.ToLower(strings.TrimSpace(alg))
	if normAlg == "" {
		normAlg = "ed25519"
	}

	var priv crypto.PrivateKey
	switch normAlg {
	case "ed25519", "ssh-ed25519":
		normAlg = "ed25519"
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, nil, "", fmt.Errorf("generate ed25519 key: %w", err)
		}
		priv = k
	case "ecdsa-p256", "ecdsa", "ecdsa-sha2-nistp256":
		normAlg = "ecdsa-p256"
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, nil, "", fmt.Errorf("generate ecdsa-p256 key: %w", err)
		}
		priv = k
	case "rsa-4096", "rsa", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		normAlg = "rsa-4096"
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, nil, nil, "", fmt.Errorf("generate rsa-4096 key: %w", err)
		}
		priv = k
	default:
		return nil, nil, nil, nil, "", fmt.Errorf("unsupported SSH key algorithm %q", alg)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, nil, nil, nil, "", fmt.Errorf("marshal SSH private key: %w", err)
	}
	privBytes := pem.EncodeToMemory(pemBlock)

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, nil, nil, "", fmt.Errorf("create SSH signer: %w", err)
	}
	sshPub := signer.PublicKey()
	pubBytes := formatAuthorizedKeyWithComment(sshPub, comment)

	return priv, sshPub, privBytes, pubBytes, normAlg, nil
}

func formatAuthorizedKeyWithComment(pub ssh.PublicKey, comment string) []byte {
	raw := bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub))
	comment = strings.TrimSpace(comment)
	if comment != "" {
		return []byte(fmt.Sprintf("%s %s\n", string(raw), comment))
	}
	return append(raw, '\n')
}

// CreateSSHCA generates an OpenSSH Certificate Authority keypair and registers it in the store.
func CreateSSHCA(s *store.Store, req SSHCARequest) (*SSHCAResult, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("SSH CA name is required")
	}
	if err := store.ValidName("SSH CA", req.Name); err != nil {
		return nil, err
	}
	caType := strings.ToLower(strings.TrimSpace(req.CAType))
	if caType == "" {
		caType = "user"
	}
	if caType != "user" && caType != "host" {
		return nil, fmt.Errorf("invalid SSH CA type %q: must be 'user' or 'host'", req.CAType)
	}

	comment := strings.TrimSpace(req.Comment)
	if comment == "" {
		comment = fmt.Sprintf("mgtls-%s-ca-%s", caType, req.Name)
	}

	var (
		sshPub    ssh.PublicKey
		privBytes []byte
		pubBytes  []byte
		normAlg   string
		err       error
	)
	if req.Signer != nil {
		sshPub = req.Signer.PublicKey()
		pubBytes = formatAuthorizedKeyWithComment(sshPub, comment)
		normAlg = req.Algorithm
		if normAlg == "" {
			normAlg = sshPub.Type()
		}
	} else {
		_, sshPub, privBytes, pubBytes, normAlg, err = generateSSHKeyPair(req.Algorithm, comment)
		if err != nil {
			return nil, err
		}
	}

	privRel := filepath.Join("ssh", "ca", req.Name, "id_ca")
	pubRel := filepath.Join("ssh", "ca", req.Name, "id_ca.pub")

	var privPath string
	if len(privBytes) > 0 {
		privPath, err = s.WriteKey(privRel, privBytes)
		if err != nil {
			return nil, err
		}
	}
	pubPath, err := s.WritePublic(pubRel, pubBytes)
	if err != nil {
		return nil, err
	}

	rec := store.SSHCARecord{
		Name:        req.Name,
		CAType:      caType,
		Algorithm:   normAlg,
		PubKeyPath:  pubPath,
		PrivKeyPath: privPath,
		Fingerprint: ssh.FingerprintSHA256(sshPub),
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.UpsertSSHCA(rec); err != nil {
		return nil, err
	}
	return &SSHCAResult{Record: rec}, nil
}

// SignSSHCert signs an OpenSSH user or host certificate using a managed SSH CA.
func SignSSHCert(s *store.Store, req SignSSHRequest) (*SignSSHResult, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("SSH certificate name is required")
	}
	if err := store.ValidName("SSH certificate", req.Name); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.CAName) == "" {
		return nil, fmt.Errorf("SSH CA name is required")
	}

	caRec, err := s.GetSSHCA(req.CAName)
	if err != nil {
		return nil, err
	}

	var caSigner ssh.Signer
	if req.CASigner != nil {
		caSigner = req.CASigner
	} else if strings.TrimSpace(req.AgentSocket) != "" {
		conn, dErr := net.Dial("unix", strings.TrimSpace(req.AgentSocket))
		if dErr != nil {
			return nil, fmt.Errorf("connect ssh-agent socket %s: %w", req.AgentSocket, dErr)
		}
		defer conn.Close()
		ag := agent.NewClient(conn)
		signers, sErr := ag.Signers()
		if sErr != nil {
			return nil, fmt.Errorf("list ssh-agent signers: %w", sErr)
		}
		for _, sg := range signers {
			if ssh.FingerprintSHA256(sg.PublicKey()) == caRec.Fingerprint {
				caSigner = sg
				break
			}
		}
		if caSigner == nil {
			return nil, fmt.Errorf("no signer in ssh-agent matching CA %q fingerprint %s", req.CAName, caRec.Fingerprint)
		}
	} else {
		caPrivRaw, rErr := os.ReadFile(caRec.PrivKeyPath)
		if rErr != nil {
			return nil, fmt.Errorf("read SSH CA private key: %w", rErr)
		}
		caSigner, err = ssh.ParsePrivateKey(caPrivRaw)
		if err != nil {
			return nil, fmt.Errorf("parse SSH CA private key: %w", err)
		}
	}

	certType := strings.ToLower(strings.TrimSpace(req.CertType))
	if certType == "" {
		certType = caRec.CAType
	}
	if caRec.CAType != "" && certType != caRec.CAType {
		return nil, fmt.Errorf("SSH CA %q is a %s CA and cannot sign %s certificates", req.CAName, caRec.CAType, certType)
	}
	if len(req.Principals) == 0 {
		// An empty ValidPrincipals list means "any user" / "any host" to OpenSSH.
		return nil, fmt.Errorf("at least one principal is required (an SSH certificate with no principals is valid for every %s)", certType)
	}
	for _, p := range req.Principals {
		if err := validatePrincipal(p, certType == "host"); err != nil {
			return nil, err
		}
	}
	if req.CASigner != nil && caRec.Fingerprint != "" && ssh.FingerprintSHA256(req.CASigner.PublicKey()) != caRec.Fingerprint {
		return nil, fmt.Errorf("supplied CA signer does not match SSH CA %q fingerprint %s", req.CAName, caRec.Fingerprint)
	}
	var sshCertType uint32
	switch certType {
	case "user":
		sshCertType = ssh.UserCert
	case "host":
		sshCertType = ssh.HostCert
	default:
		return nil, fmt.Errorf("invalid SSH certificate type %q: must be 'user' or 'host'", certType)
	}

	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		keyID = req.Name
	}
	if hasControlChars(keyID) {
		return nil, fmt.Errorf("SSH key ID must not contain control characters")
	}
	if req.ValidHours > maxSSHValidHours {
		return nil, fmt.Errorf("valid_hours %d exceeds maximum %d", req.ValidHours, maxSSHValidHours)
	}

	validHours := req.ValidHours
	if validHours <= 0 {
		if certType == "user" {
			validHours = 720
		} else {
			validHours = 8760
		}
	}

	var (
		sshPub   ssh.PublicKey
		privPath string
		pubPath  string
	)

	pubRel := filepath.Join("ssh", "certs", req.Name, "id_key.pub")
	if strings.TrimSpace(req.ExistingPubKey) != "" {
		rawPub, err := os.ReadFile(req.ExistingPubKey)
		if err != nil {
			return nil, fmt.Errorf("read existing public key %s: %w", req.ExistingPubKey, err)
		}
		parsedPub, _, _, _, err := ssh.ParseAuthorizedKey(rawPub)
		if err != nil {
			return nil, fmt.Errorf("parse existing public key %s: %w", req.ExistingPubKey, err)
		}
		sshPub = parsedPub
		pubPath, err = s.WritePublic(pubRel, formatAuthorizedKeyWithComment(sshPub, keyID))
		if err != nil {
			return nil, err
		}
	} else {
		alg := req.Algorithm
		if strings.TrimSpace(alg) == "" {
			alg = caRec.Algorithm
		}
		_, generatedPub, privBytes, pubBytes, _, err := generateSSHKeyPair(alg, keyID)
		if err != nil {
			return nil, err
		}
		sshPub = generatedPub
		privRel := filepath.Join("ssh", "certs", req.Name, "id_key")
		privPath, err = s.WriteKey(privRel, privBytes)
		if err != nil {
			return nil, err
		}
		pubPath, err = s.WritePublic(pubRel, pubBytes)
		if err != nil {
			return nil, err
		}
	}

	var serialBytes [8]byte
	if _, err := rand.Read(serialBytes[:]); err != nil {
		return nil, fmt.Errorf("generate SSH certificate serial: %w", err)
	}
	serial := binary.BigEndian.Uint64(serialBytes[:])
	if serial == 0 {
		serial = 1
	}

	now := time.Now().UTC()
	validAfter := time.Unix(now.Add(-1*time.Minute).Unix(), 0).UTC()
	validBefore := time.Unix(now.Add(time.Duration(validHours)*time.Hour).Unix(), 0).UTC()

	critOpts := map[string]string{}
	for k, v := range req.CriticalOptions {
		critOpts[k] = v
	}

	exts := map[string]string{}
	if req.Extensions != nil {
		for k, v := range req.Extensions {
			exts[k] = v
		}
	} else if certType == "user" {
		exts = map[string]string{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		}
	}

	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          serial,
		CertType:        sshCertType,
		KeyId:           keyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: critOpts,
			Extensions:      exts,
		},
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("sign SSH certificate: %w", err)
	}

	certBytes := formatAuthorizedKeyWithComment(cert, keyID)
	certRel := filepath.Join("ssh", "certs", req.Name, "id_key-cert.pub")
	certPath, err := s.WritePublic(certRel, certBytes)
	if err != nil {
		return nil, err
	}

	rec := store.SSHCertRecord{
		Name:        req.Name,
		CAName:      req.CAName,
		CertType:    certType,
		KeyID:       keyID,
		Serial:      serial,
		Principals:  req.Principals,
		CertPath:    certPath,
		PubKeyPath:  pubPath,
		PrivKeyPath: privPath,
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
	}
	if err := s.UpsertSSHCert(rec); err != nil {
		return nil, err
	}

	return &SignSSHResult{Record: rec}, nil
}

// InspectSSHCert reads and decodes an OpenSSH certificate file (-cert.pub).
func InspectSSHCert(certPath string) (*SSHCertInfo, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH certificate %s: %w", certPath, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse SSH authorized key %s: %w", certPath, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("file %s does not contain an OpenSSH certificate", certPath)
	}

	var certType string
	switch cert.CertType {
	case ssh.UserCert:
		certType = "user"
	case ssh.HostCert:
		certType = "host"
	default:
		certType = fmt.Sprintf("unknown(%d)", cert.CertType)
	}

	return &SSHCertInfo{
		KeyID:           cert.KeyId,
		Serial:          cert.Serial,
		CertType:        certType,
		Principals:      cert.ValidPrincipals,
		ValidAfter:      time.Unix(int64(cert.ValidAfter), 0).UTC(),
		ValidBefore:     time.Unix(int64(cert.ValidBefore), 0).UTC(),
		CAFingerprint:   ssh.FingerprintSHA256(cert.SignatureKey),
		KeyFingerprint:  ssh.FingerprintSHA256(cert.Key),
		CriticalOptions: cert.CriticalOptions,
		Extensions:      cert.Extensions,
	}, nil
}

func getSSHCertRecord(s *store.Store, name string) (*store.SSHCertRecord, error) {
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}
	for _, c := range m.SSHCerts {
		if c.Name == name {
			cp := c
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("SSH certificate %q not found in store", name)
}

// GenerateSSHConfigBundle generates OpenSSH server and client configuration drop-ins, known_hosts, and authorized_principals.
func GenerateSSHConfigBundle(s *store.Store, req SSHConfigRequest) (*SSHConfigBundle, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "default"
	}
	if err := store.ValidName("SSH config bundle", name); err != nil {
		return nil, err
	}

	outDir := strings.TrimSpace(req.OutputDir)
	if outDir == "" {
		outDir = s.Path("ssh", "bundles", name)
	} else {
		abs, err := filepath.Abs(outDir)
		if err != nil {
			return nil, fmt.Errorf("resolve output dir: %w", err)
		}
		outDir = abs
	}

	sshdDropInDir := filepath.Join(outDir, "sshd_config.d")
	sshClientDropInDir := filepath.Join(outDir, "ssh_config.d")
	for _, d := range []string{outDir, sshdDropInDir, sshClientDropInDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	files := make(map[string]string)

	var userCAPubPath string
	if strings.TrimSpace(req.UserCAName) != "" {
		userCA, err := s.GetSSHCA(req.UserCAName)
		if err != nil {
			return nil, err
		}
		rawPub, err := os.ReadFile(userCA.PubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read user CA pubkey: %w", err)
		}
		userCAPubPath = filepath.Join(outDir, "user_ca.pub")
		if err := os.WriteFile(userCAPubPath, rawPub, 0644); err != nil {
			return nil, fmt.Errorf("write user_ca.pub: %w", err)
		}
		files["user_ca.pub"] = userCAPubPath
	}

	var hostCertRec *store.SSHCertRecord
	if strings.TrimSpace(req.HostCertName) != "" {
		rec, err := getSSHCertRecord(s, req.HostCertName)
		if err != nil {
			return nil, err
		}
		hostCertRec = rec
	}

	var userCertRec *store.SSHCertRecord
	if strings.TrimSpace(req.UserCertName) != "" {
		rec, err := getSSHCertRecord(s, req.UserCertName)
		if err != nil {
			return nil, err
		}
		userCertRec = rec
	}

	principals := req.Principals
	if len(principals) == 0 && userCertRec != nil && len(userCertRec.Principals) > 0 {
		principals = userCertRec.Principals
	}
	if len(principals) == 0 && strings.TrimSpace(req.UserCAName) != "" {
		// Previously defaulted to root+admin, silently authorizing privileged logins.
		return nil, fmt.Errorf("principals are required when trusting a user CA")
	}
	for _, p := range principals {
		if err := validatePrincipal(p, false); err != nil {
			return nil, err
		}
	}
	for _, hp := range req.HostPatterns {
		if !hostPatternRE.MatchString(hp) {
			return nil, fmt.Errorf("invalid host pattern %q: allowed characters are letters, digits and . * ? ! : - _ [ ]", hp)
		}
	}
	if hasControlChars(outDir) || strings.ContainsAny(outDir, " \t\"") {
		return nil, fmt.Errorf("output dir %q must not contain whitespace, quotes or control characters (it is written unquoted into sshd/ssh config)", outDir)
	}

	authPrincipalsPath := filepath.Join(outDir, "authorized_principals")
	authPrincipalsContent := strings.Join(principals, "\n") + "\n"
	if err := os.WriteFile(authPrincipalsPath, []byte(authPrincipalsContent), 0644); err != nil {
		return nil, fmt.Errorf("write authorized_principals: %w", err)
	}
	files["authorized_principals"] = authPrincipalsPath

	var sshdBuf strings.Builder
	sshdBuf.WriteString("# Generated by mgtls\n")
	if userCAPubPath != "" {
		sshdBuf.WriteString(fmt.Sprintf("TrustedUserCAKeys %s\n", userCAPubPath))
	}
	if hostCertRec != nil {
		if hostCertRec.PrivKeyPath != "" {
			sshdBuf.WriteString(fmt.Sprintf("HostKey %s\n", hostCertRec.PrivKeyPath))
		}
		sshdBuf.WriteString(fmt.Sprintf("HostCertificate %s\n", hostCertRec.CertPath))
	}
	sshdBuf.WriteString(fmt.Sprintf("AuthorizedPrincipalsFile %s\n", authPrincipalsPath))

	sshdConfigPath := filepath.Join(sshdDropInDir, "mgtls-ca.conf")
	if err := os.WriteFile(sshdConfigPath, []byte(sshdBuf.String()), 0644); err != nil {
		return nil, fmt.Errorf("write sshd_config drop-in: %w", err)
	}
	files["sshd_config"] = sshdConfigPath

	knownHostsPath := filepath.Join(outDir, "known_hosts")
	var knownHostsBuf strings.Builder
	if strings.TrimSpace(req.HostCAName) != "" {
		hostCA, err := s.GetSSHCA(req.HostCAName)
		if err != nil {
			return nil, err
		}
		rawHostCAPub, err := os.ReadFile(hostCA.PubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read host CA pubkey: %w", err)
		}
		patterns := req.HostPatterns
		if len(patterns) == 0 {
			patterns = []string{"*"}
		}
		knownHostsBuf.WriteString(fmt.Sprintf("@cert-authority %s %s\n",
			strings.Join(patterns, ","),
			strings.TrimSpace(string(rawHostCAPub)),
		))
	}
	if err := os.WriteFile(knownHostsPath, []byte(knownHostsBuf.String()), 0644); err != nil {
		return nil, fmt.Errorf("write known_hosts: %w", err)
	}
	files["known_hosts"] = knownHostsPath

	var sshClientBuf strings.Builder
	sshClientBuf.WriteString("# Generated by mgtls\n")
	hostMatch := "*"
	if len(req.HostPatterns) > 0 {
		hostMatch = strings.Join(req.HostPatterns, " ")
	}
	sshClientBuf.WriteString(fmt.Sprintf("Host %s\n", hostMatch))
	sshClientBuf.WriteString(fmt.Sprintf("    UserKnownHostsFile %s\n", knownHostsPath))
	if userCertRec != nil {
		if userCertRec.PrivKeyPath != "" {
			sshClientBuf.WriteString(fmt.Sprintf("    IdentityFile %s\n", userCertRec.PrivKeyPath))
		}
		sshClientBuf.WriteString(fmt.Sprintf("    CertificateFile %s\n", userCertRec.CertPath))
	}

	sshClientConfigPath := filepath.Join(sshClientDropInDir, "mgtls.conf")
	if err := os.WriteFile(sshClientConfigPath, []byte(sshClientBuf.String()), 0644); err != nil {
		return nil, fmt.Errorf("write ssh_config drop-in: %w", err)
	}
	files["ssh_client_config"] = sshClientConfigPath

	return &SSHConfigBundle{
		OutputDir:            outDir,
		SSHDConfigPath:       sshdConfigPath,
		SSHClientConfigPath:  sshClientConfigPath,
		KnownHostsPath:       knownHostsPath,
		AuthorizedPrincipals: authPrincipalsPath,
		Files:                files,
	}, nil
}

// maxSSHValidHours caps certificate lifetime (10 years) and keeps
// time.Duration(validHours)*time.Hour far from int64 overflow.
const maxSSHValidHours = 24 * 365 * 10

var (
	principalRE     = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,255}$`)
	hostPrincipalRE = regexp.MustCompile(`^[A-Za-z0-9._@+*?-]{1,255}$`)
	hostPatternRE   = regexp.MustCompile(`^[A-Za-z0-9.*?!:_\[\]-]{1,255}$`)
)

// validatePrincipal rejects principals that are empty, contain whitespace, commas,
// newlines (which would inject extra lines into authorized_principals). Wildcards
// (* ?) are allowed only for host certificates, where OpenSSH clients match them.
func validatePrincipal(p string, host bool) error {
	re := principalRE
	if host {
		re = hostPrincipalRE
	}
	if !re.MatchString(p) {
		return fmt.Errorf("invalid SSH principal %q: use letters, digits and . _ @ + -", p)
	}
	return nil
}

func hasControlChars(v string) bool {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
