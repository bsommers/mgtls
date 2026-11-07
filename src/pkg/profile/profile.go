package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/acme"
	"github.com/sysadmin/mgtls/src/pkg/pki"
	"github.com/sysadmin/mgtls/src/pkg/sshca"
	"github.com/sysadmin/mgtls/src/pkg/store"
	"github.com/sysadmin/mgtls/src/pkg/targets"
)

type FleetSpec struct {
	Version    string                    `json:"version" yaml:"version"`
	StoreDir   string                    `json:"store_dir,omitempty" yaml:"store_dir,omitempty"`
	CAs        []pki.CARequest           `json:"cas,omitempty" yaml:"cas,omitempty"`
	SelfSigned []pki.SelfSignedRequest   `json:"self_signed,omitempty" yaml:"self_signed,omitempty"`
	Certs      []pki.CertRequest         `json:"certs,omitempty" yaml:"certs,omitempty"`
	SSHCAs     []sshca.SSHCARequest      `json:"ssh_cas,omitempty" yaml:"ssh_cas,omitempty"`
	SSHCerts   []sshca.SignSSHRequest    `json:"ssh_certs,omitempty" yaml:"ssh_certs,omitempty"`
	SSHConfigs []sshca.SSHConfigRequest  `json:"ssh_configs,omitempty" yaml:"ssh_configs,omitempty"`
	ACMECerts  []acme.ObtainRequest      `json:"acme_certs,omitempty" yaml:"acme_certs,omitempty"`
	Targets    []targets.GenerateRequest `json:"targets,omitempty" yaml:"targets,omitempty"`
}

type ApplyReport struct {
	CAsCreated        []string `json:"cas_created"`
	SelfSignedCreated []string `json:"self_signed_created"`
	CertsIssued       []string `json:"certs_issued"`
	SSHCAsCreated     []string `json:"ssh_cas_created"`
	SSHCertsSigned    []string `json:"ssh_certs_signed"`
	SSHConfigsBuilt   []string `json:"ssh_configs_built"`
	ACMECertsObtained []string `json:"acme_certs_obtained"`
	TargetsGenerated  []string `json:"targets_generated"`
}

type DoctorFinding struct {
	Severity string `json:"severity"` // "ok", "warning", "error"
	Kind     string `json:"kind"`     // "ca", "cert", "ssh_ca", "ssh_cert", "acme", "permissions"
	Name     string `json:"name"`
	Message  string `json:"message"`
}

type DoctorReport struct {
	Healthy  bool            `json:"healthy"`
	Findings []DoctorFinding `json:"findings"`
}

// WatchOptions configures autonomous renewal and hook execution.
type WatchOptions struct {
	ManifestPath string        `json:"manifest_path"`
	Interval     time.Duration `json:"interval"`
	RenewBefore  time.Duration `json:"renew_before"`
	OnRenewHook  string        `json:"on_renew_hook,omitempty"`
	Once         bool          `json:"once"`
}

// RenewalCycleReport summarizes a single autonomous renewal pass.
type RenewalCycleReport struct {
	CheckedAt          time.Time `json:"checked_at"`
	RenewedCerts       []string  `json:"renewed_certs"`
	RenewedSelfSigned  []string  `json:"renewed_self_signed"`
	RenewedSSHCerts    []string  `json:"renewed_ssh_certs"`
	RenewedACMECerts   []string  `json:"renewed_acme_certs"`
	RegeneratedTargets []string  `json:"regenerated_targets"`
	HookExecuted       bool      `json:"hook_executed"`
	HookOutput         string    `json:"hook_output,omitempty"`
	// Errors lists per-item failures; the cycle continues past them so one bad
	// certificate cannot block renewal, target regeneration or the hook for others.
	Errors []string `json:"errors,omitempty"`
}

// onRenewHookTimeout bounds the --on-renew hook so a hung reload cannot wedge the daemon.
const onRenewHookTimeout = 5 * time.Minute

// SystemdRequest configures systemd .service and .timer unit generation.
type SystemdRequest struct {
	UnitName     string `json:"unit_name"`
	BinaryPath   string `json:"binary_path"`
	ManifestPath string `json:"manifest_path"`
	StoreDir     string `json:"store_dir"`
	Calendar     string `json:"calendar"`     // e.g. "*-*-* 00,12:00:00"
	RenewBefore  string `json:"renew_before"` // e.g. "720h" (30d)
	OnRenewHook  string `json:"on_renew_hook,omitempty"`
	OutputDir    string `json:"output_dir"`
}

// SystemdBundle holds paths and contents of generated systemd units.
type SystemdBundle struct {
	ServicePath string   `json:"service_path"`
	TimerPath   string   `json:"timer_path"`
	InstallCmds []string `json:"install_cmds"`
}

// LoadFleetSpec reads and parses a YAML or JSON fleet manifest from disk.
func LoadFleetSpec(path string) (*FleetSpec, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("fleet spec path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fleet spec %s: %w", path, err)
	}
	return ParseFleetSpec(data)
}

// ParseFleetSpec parses YAML or JSON bytes into a FleetSpec.
func ParseFleetSpec(data []byte) (*FleetSpec, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("fleet spec is empty")
	}

	var spec FleetSpec
	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &spec); err != nil {
			return nil, fmt.Errorf("parse JSON fleet spec: %w", err)
		}
		return &spec, nil
	}

	rawObj, err := parseYAMLToObject(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse YAML fleet spec: %w", err)
	}
	jsonBytes, err := json.Marshal(rawObj)
	if err != nil {
		return nil, fmt.Errorf("encode parsed YAML spec: %w", err)
	}
	if err := json.Unmarshal(jsonBytes, &spec); err != nil {
		return nil, fmt.Errorf("decode fleet spec: %w", err)
	}
	return &spec, nil
}

// Apply provisions all CAs, certificates, SSH CAs/certs/configs, ACME certs, and target bundles declared in spec.
func Apply(ctx context.Context, s *store.Store, spec *FleetSpec) (*ApplyReport, error) {
	if spec == nil {
		return nil, errors.New("fleet spec is nil")
	}
	if s == nil {
		var err error
		s, err = store.New(spec.StoreDir)
		if err != nil {
			return nil, err
		}
	}
	if err := s.Init(); err != nil {
		return nil, err
	}

	report := &ApplyReport{
		CAsCreated:        []string{},
		SelfSignedCreated: []string{},
		CertsIssued:       []string{},
		SSHCAsCreated:     []string{},
		SSHCertsSigned:    []string{},
		SSHConfigsBuilt:   []string{},
		ACMECertsObtained: []string{},
		TargetsGenerated:  []string{},
	}

	for _, req := range spec.CAs {
		res, err := pki.CreateCA(s, req)
		if err != nil && req.ParentCA != "" && strings.Contains(err.Error(), "SignatureAlgorithm does not match private key type") {
			if parentCA, pErr := s.GetCA(req.ParentCA); pErr == nil {
				retryReq := req
				retryReq.Algorithm = parentCA.Algorithm
				res, err = pki.CreateCA(s, retryReq)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("apply CA %q: %w", req.Name, err)
		}
		report.CAsCreated = append(report.CAsCreated, res.Record.Name)
	}

	for _, req := range spec.SelfSigned {
		res, err := pki.IssueSelfSigned(s, req)
		if err != nil {
			return nil, fmt.Errorf("apply self-signed cert %q: %w", req.Name, err)
		}
		report.SelfSignedCreated = append(report.SelfSignedCreated, res.Record.Name)
	}

	for _, req := range spec.Certs {
		res, err := pki.IssueCert(s, req)
		if err != nil {
			return nil, fmt.Errorf("apply cert %q: %w", req.Name, err)
		}
		report.CertsIssued = append(report.CertsIssued, res.Record.Name)
	}

	for _, req := range spec.SSHCAs {
		res, err := sshca.CreateSSHCA(s, req)
		if err != nil {
			return nil, fmt.Errorf("apply SSH CA %q: %w", req.Name, err)
		}
		report.SSHCAsCreated = append(report.SSHCAsCreated, res.Record.Name)
	}

	for _, req := range spec.SSHCerts {
		res, err := sshca.SignSSHCert(s, req)
		if err != nil {
			return nil, fmt.Errorf("apply SSH cert %q: %w", req.Name, err)
		}
		report.SSHCertsSigned = append(report.SSHCertsSigned, res.Record.Name)
	}

	for _, req := range spec.SSHConfigs {
		if _, err := sshca.GenerateSSHConfigBundle(s, req); err != nil {
			return nil, fmt.Errorf("apply SSH config %q: %w", req.Name, err)
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "default"
		}
		report.SSHConfigsBuilt = append(report.SSHConfigsBuilt, name)
	}

	for _, req := range spec.ACMECerts {
		res, err := acme.ObtainCertificate(ctx, s, req)
		if err != nil {
			return nil, fmt.Errorf("apply ACME cert %q: %w", req.Name, err)
		}
		report.ACMECertsObtained = append(report.ACMECertsObtained, res.Record.Name)
	}

	for _, req := range spec.Targets {
		resolvedReq, err := resolveTargetPaths(s, req)
		if err != nil {
			return nil, fmt.Errorf("resolve target %q paths: %w", req.Name, err)
		}
		res, err := targets.Generate(s, resolvedReq)
		if err != nil {
			return nil, fmt.Errorf("apply target %q: %w", req.Name, err)
		}
		report.TargetsGenerated = append(report.TargetsGenerated, res.Record.Name)
	}

	return report, nil
}

func resolveTargetPaths(s *store.Store, req targets.GenerateRequest) (targets.GenerateRequest, error) {
	if req.CAName != "" && req.CACertPath == "" {
		if caRec, err := s.GetCA(req.CAName); err == nil {
			if caRec.ChainPath != "" {
				req.CACertPath = caRec.ChainPath
			} else {
				req.CACertPath = caRec.CertPath
			}
		} else if sshCA, sshErr := s.GetSSHCA(req.CAName); sshErr == nil {
			req.CACertPath = sshCA.PubKeyPath
		} else {
			return req, err
		}
	}

	if req.ServerCert != "" && (req.ServerCertPath == "" || req.ServerKeyPath == "") {
		if srvRec, err := s.GetCert(req.ServerCert); err == nil {
			if req.ServerCertPath == "" {
				if srvRec.FullChainPath != "" {
					req.ServerCertPath = srvRec.FullChainPath
				} else {
					req.ServerCertPath = srvRec.CertPath
				}
			}
			if req.ServerKeyPath == "" {
				req.ServerKeyPath = srvRec.KeyPath
			}
			if req.CACertPath == "" && srvRec.CAChainPath != "" {
				req.CACertPath = srvRec.CAChainPath
			}
		} else if sshCert, ok := findSSHCert(s, req.ServerCert); ok {
			if req.ServerCertPath == "" {
				req.ServerCertPath = sshCert.CertPath
			}
			if req.ServerKeyPath == "" {
				req.ServerKeyPath = sshCert.PrivKeyPath
			}
		} else if acmeCert, ok := findACMECert(s, req.ServerCert); ok {
			if req.ServerCertPath == "" {
				req.ServerCertPath = acmeCert.CertPath
			}
			if req.ServerKeyPath == "" {
				req.ServerKeyPath = acmeCert.KeyPath
			}
		} else {
			return req, err
		}
	}

	if req.ClientCert != "" && (req.ClientCertPath == "" || req.ClientKeyPath == "") {
		if cliRec, err := s.GetCert(req.ClientCert); err == nil {
			if req.ClientCertPath == "" {
				req.ClientCertPath = cliRec.CertPath
			}
			if req.ClientKeyPath == "" {
				req.ClientKeyPath = cliRec.KeyPath
			}
		} else if sshCert, ok := findSSHCert(s, req.ClientCert); ok {
			if req.ClientCertPath == "" {
				req.ClientCertPath = sshCert.CertPath
			}
			if req.ClientKeyPath == "" {
				req.ClientKeyPath = sshCert.PrivKeyPath
			}
		} else {
			return req, err
		}
	}

	return req, nil
}

func findSSHCert(s *store.Store, name string) (store.SSHCertRecord, bool) {
	m, err := s.LoadManifest()
	if err != nil {
		return store.SSHCertRecord{}, false
	}
	for _, c := range m.SSHCerts {
		if c.Name == name {
			return c, true
		}
	}
	return store.SSHCertRecord{}, false
}

func findACMECert(s *store.Store, name string) (store.ACMERecord, bool) {
	m, err := s.LoadManifest()
	if err != nil {
		return store.ACMERecord{}, false
	}
	for _, c := range m.ACMECerts {
		if c.Name == name {
			return c, true
		}
	}
	return store.ACMERecord{}, false
}

// RunDoctor inspects all store artifacts for missing files, insecure key permissions, revocation, and upcoming or past expiration.
func RunDoctor(s *store.Store, warnDays int) (*DoctorReport, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if warnDays <= 0 {
		warnDays = 30
	}
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	warnCutoff := now.Add(time.Duration(warnDays)*24*time.Hour - 5*time.Minute)

	report := &DoctorReport{
		Healthy:  true,
		Findings: []DoctorFinding{},
	}

	addFinding := func(f DoctorFinding) {
		if f.Severity != "ok" {
			report.Healthy = false
		}
		report.Findings = append(report.Findings, f)
	}

	checkKeyFile := func(ownerKind, name, path string) bool {
		info, err := os.Stat(path)
		if err != nil {
			addFinding(DoctorFinding{
				Severity: "error",
				Kind:     ownerKind,
				Name:     name,
				Message:  fmt.Sprintf("private key file missing: %s", path),
			})
			return false
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			addFinding(DoctorFinding{
				Severity: "error",
				Kind:     "permissions",
				Name:     name,
				Message:  fmt.Sprintf("private key %s has insecure permissions %04o (expected 0600)", path, perm),
			})
			return false
		}
		return true
	}

	checkPublicFile := func(ownerKind, name, label, path string) bool {
		if _, err := os.Stat(path); err != nil {
			addFinding(DoctorFinding{
				Severity: "error",
				Kind:     ownerKind,
				Name:     name,
				Message:  fmt.Sprintf("%s file missing: %s", label, path),
			})
			return false
		}
		return true
	}

	for _, ca := range m.CAs {
		certOK := checkPublicFile("ca", ca.Name, "CA certificate", ca.CertPath)
		keyOK := true
		if ca.KeyPath != "" {
			keyOK = checkKeyFile("ca", ca.Name, ca.KeyPath)
		}
		if !ca.NotAfter.After(now) {
			addFinding(DoctorFinding{
				Severity: "error",
				Kind:     "ca",
				Name:     ca.Name,
				Message:  fmt.Sprintf("CA %q expired at %s", ca.Name, ca.NotAfter.Format(time.RFC3339)),
			})
		} else if ca.NotAfter.Before(warnCutoff) {
			addFinding(DoctorFinding{
				Severity: "warning",
				Kind:     "ca",
				Name:     ca.Name,
				Message:  fmt.Sprintf("CA %q expires soon at %s", ca.Name, ca.NotAfter.Format(time.RFC3339)),
			})
		} else if certOK && keyOK {
			addFinding(DoctorFinding{
				Severity: "ok",
				Kind:     "ca",
				Name:     ca.Name,
				Message:  fmt.Sprintf("CA %q is valid until %s", ca.Name, ca.NotAfter.Format(time.RFC3339)),
			})
		}
	}

	for _, cert := range m.Certs {
		certOK := checkPublicFile("cert", cert.Name, "certificate", cert.CertPath)
		keyOK := checkKeyFile("cert", cert.Name, cert.KeyPath)
		if cert.Revoked {
			addFinding(DoctorFinding{
				Severity: "warning",
				Kind:     "cert",
				Name:     cert.Name,
				Message:  fmt.Sprintf("certificate %q is revoked", cert.Name),
			})
		} else if !cert.NotAfter.After(now) {
			addFinding(DoctorFinding{
				Severity: "error",
				Kind:     "cert",
				Name:     cert.Name,
				Message:  fmt.Sprintf("certificate %q expired at %s", cert.Name, cert.NotAfter.Format(time.RFC3339)),
			})
		} else if cert.NotAfter.Before(warnCutoff) {
			addFinding(DoctorFinding{
				Severity: "warning",
				Kind:     "cert",
				Name:     cert.Name,
				Message:  fmt.Sprintf("certificate %q expires soon at %s", cert.Name, cert.NotAfter.Format(time.RFC3339)),
			})
		} else if certOK && keyOK {
			addFinding(DoctorFinding{
				Severity: "ok",
				Kind:     "cert",
				Name:     cert.Name,
				Message:  fmt.Sprintf("certificate %q is valid until %s", cert.Name, cert.NotAfter.Format(time.RFC3339)),
			})
		}
	}

	for _, ca := range m.SSHCAs {
		pubOK := checkPublicFile("ssh_ca", ca.Name, "SSH CA public key", ca.PubKeyPath)
		privOK := true
		if ca.PrivKeyPath != "" {
			privOK = checkKeyFile("ssh_ca", ca.Name, ca.PrivKeyPath)
		}
		if pubOK && privOK {
			addFinding(DoctorFinding{
				Severity: "ok",
				Kind:     "ssh_ca",
				Name:     ca.Name,
				Message:  fmt.Sprintf("SSH CA %q (%s) is healthy", ca.Name, ca.CAType),
			})
		}
	}

	for _, sc := range m.SSHCerts {
		certOK := checkPublicFile("ssh_cert", sc.Name, "SSH certificate", sc.CertPath)
		keyOK := true
		if sc.PrivKeyPath != "" {
			keyOK = checkKeyFile("ssh_cert", sc.Name, sc.PrivKeyPath)
		}
		if !sc.ValidBefore.IsZero() && !sc.ValidBefore.After(now) {
			addFinding(DoctorFinding{
				Severity: "error",
				Kind:     "ssh_cert",
				Name:     sc.Name,
				Message:  fmt.Sprintf("SSH certificate %q expired at %s", sc.Name, sc.ValidBefore.Format(time.RFC3339)),
			})
		} else if !sc.ValidBefore.IsZero() && sc.ValidBefore.Before(warnCutoff) {
			addFinding(DoctorFinding{
				Severity: "warning",
				Kind:     "ssh_cert",
				Name:     sc.Name,
				Message:  fmt.Sprintf("SSH certificate %q expires soon at %s", sc.Name, sc.ValidBefore.Format(time.RFC3339)),
			})
		} else if certOK && keyOK {
			addFinding(DoctorFinding{
				Severity: "ok",
				Kind:     "ssh_cert",
				Name:     sc.Name,
				Message:  fmt.Sprintf("SSH certificate %q is valid until %s", sc.Name, sc.ValidBefore.Format(time.RFC3339)),
			})
		}
	}

	for _, ac := range m.ACMECerts {
		certOK := checkPublicFile("acme", ac.Name, "ACME certificate", ac.CertPath)
		keyOK := checkKeyFile("acme", ac.Name, ac.KeyPath)
		acctOK := true
		if ac.AccountKey != "" {
			acctOK = checkKeyFile("acme", ac.Name, ac.AccountKey)
		}
		if !ac.NotAfter.IsZero() && !ac.NotAfter.After(now) {
			addFinding(DoctorFinding{
				Severity: "error",
				Kind:     "acme",
				Name:     ac.Name,
				Message:  fmt.Sprintf("ACME certificate %q expired at %s", ac.Name, ac.NotAfter.Format(time.RFC3339)),
			})
		} else if !ac.NotAfter.IsZero() && ac.NotAfter.Before(warnCutoff) {
			addFinding(DoctorFinding{
				Severity: "warning",
				Kind:     "acme",
				Name:     ac.Name,
				Message:  fmt.Sprintf("ACME certificate %q expires soon at %s", ac.Name, ac.NotAfter.Format(time.RFC3339)),
			})
		} else if certOK && keyOK && acctOK {
			addFinding(DoctorFinding{
				Severity: "ok",
				Kind:     "acme",
				Name:     ac.Name,
				Message:  fmt.Sprintf("ACME certificate %q is valid until %s", ac.Name, ac.NotAfter.Format(time.RFC3339)),
			})
		}
	}

	return report, nil
}

// RunRenewalCycle inspects the store and manifest, renews any leaf certificates, self-signed certificates, SSH certificates, or ACME certificates expiring within renewBefore, regenerates targets if any renewal occurred, and optionally runs onRenewHook.
func RunRenewalCycle(ctx context.Context, s *store.Store, spec *FleetSpec, renewBefore time.Duration, onRenewHook string) (*RenewalCycleReport, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if renewBefore <= 0 {
		renewBefore = 30 * 24 * time.Hour
	}
	if err := s.Init(); err != nil {
		return nil, err
	}
	m, err := s.LoadManifest()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	cutoff := now.Add(renewBefore)

	rep := &RenewalCycleReport{
		CheckedAt:          now,
		RenewedCerts:       []string{},
		RenewedSelfSigned:  []string{},
		RenewedSSHCerts:    []string{},
		RenewedACMECerts:   []string{},
		RegeneratedTargets: []string{},
	}

	var errs []error
	certNeedsRenewal := make(map[string]bool)
	for _, c := range m.Certs {
		if c.Revoked || c.NotAfter.Before(cutoff) {
			certNeedsRenewal[c.Name] = true
		}
	}
	sshNeedsRenewal := make(map[string]bool)
	for _, sc := range m.SSHCerts {
		if !sc.ValidBefore.IsZero() && sc.ValidBefore.Before(cutoff) {
			sshNeedsRenewal[sc.Name] = true
		}
	}
	acmeNeedsRenewal := make(map[string]bool)
	for _, ac := range m.ACMECerts {
		if !ac.NotAfter.IsZero() && ac.NotAfter.Before(cutoff) {
			acmeNeedsRenewal[ac.Name] = true
		}
	}

	if spec != nil {
		for _, req := range spec.SelfSigned {
			if _, exists := s.GetCert(req.Name); exists != nil || certNeedsRenewal[req.Name] {
				res, err := pki.IssueSelfSigned(s, req)
				if err != nil {
					errs = append(errs, fmt.Errorf("renew self-signed cert %q: %w", req.Name, err))
					continue
				}
				rep.RenewedSelfSigned = append(rep.RenewedSelfSigned, res.Record.Name)
			}
		}
		for _, req := range spec.Certs {
			if _, exists := s.GetCert(req.Name); exists != nil || certNeedsRenewal[req.Name] {
				res, err := pki.IssueCert(s, req)
				if err != nil {
					errs = append(errs, fmt.Errorf("renew cert %q: %w", req.Name, err))
					continue
				}
				rep.RenewedCerts = append(rep.RenewedCerts, res.Record.Name)
			}
		}
		for _, req := range spec.SSHCerts {
			if _, exists := findSSHCert(s, req.Name); !exists || sshNeedsRenewal[req.Name] {
				res, err := sshca.SignSSHCert(s, req)
				if err != nil {
					errs = append(errs, fmt.Errorf("renew SSH cert %q: %w", req.Name, err))
					continue
				}
				rep.RenewedSSHCerts = append(rep.RenewedSSHCerts, res.Record.Name)
			}
		}
		for _, req := range spec.ACMECerts {
			if _, exists := findACMECert(s, req.Name); !exists || acmeNeedsRenewal[req.Name] {
				res, err := acme.ObtainCertificate(ctx, s, req)
				if err != nil {
					errs = append(errs, fmt.Errorf("renew ACME cert %q: %w", req.Name, err))
					continue
				}
				rep.RenewedACMECerts = append(rep.RenewedACMECerts, res.Record.Name)
			}
		}
	} else {
		// Store-only mode (no manifest provided): re-issue expiring X.509 certs from their stored metadata
		for _, c := range m.Certs {
			if !certNeedsRenewal[c.Name] {
				continue
			}
			if c.SelfSigned {
				res, err := pki.IssueSelfSigned(s, pki.SelfSignedRequest{
					Name:        c.Name,
					CommonName:  c.CommonName,
					Role:        c.Role,
					Algorithm:   c.Algorithm,
					DNSNames:    c.DNSNames,
					IPAddresses: c.IPAddresses,
					URIs:        c.URIs,
				})
				if err != nil {
					errs = append(errs, fmt.Errorf("renew store self-signed cert %q: %w", c.Name, err))
					continue
				}
				rep.RenewedSelfSigned = append(rep.RenewedSelfSigned, res.Record.Name)
			} else if c.CAName != "" {
				res, err := pki.IssueCert(s, pki.CertRequest{
					Name:        c.Name,
					CommonName:  c.CommonName,
					CAName:      c.CAName,
					Role:        c.Role,
					Algorithm:   c.Algorithm,
					DNSNames:    c.DNSNames,
					IPAddresses: c.IPAddresses,
					URIs:        c.URIs,
				})
				if err != nil {
					errs = append(errs, fmt.Errorf("renew store cert %q: %w", c.Name, err))
					continue
				}
				rep.RenewedCerts = append(rep.RenewedCerts, res.Record.Name)
			}
		}
	}

	totalRenewed := len(rep.RenewedCerts) + len(rep.RenewedSelfSigned) + len(rep.RenewedSSHCerts) + len(rep.RenewedACMECerts)
	if totalRenewed > 0 {
		if spec != nil {
			for _, req := range spec.Targets {
				resolvedReq, err := resolveTargetPaths(s, req)
				if err != nil {
					errs = append(errs, fmt.Errorf("resolve target %q after renewal: %w", req.Name, err))
					continue
				}
				res, err := targets.Generate(s, resolvedReq)
				if err != nil {
					errs = append(errs, fmt.Errorf("regenerate target %q after renewal: %w", req.Name, err))
					continue
				}
				rep.RegeneratedTargets = append(rep.RegeneratedTargets, res.Record.Name)
			}
		}
		if strings.TrimSpace(onRenewHook) != "" {
			hookCtx, cancel := context.WithTimeout(ctx, onRenewHookTimeout)
			defer cancel()
			cmd := exec.CommandContext(hookCtx, "sh", "-c", onRenewHook)
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("MGTLS_STORE_DIR=%s", s.BaseDir),
				fmt.Sprintf("MGTLS_RENEWED_COUNT=%d", totalRenewed),
				fmt.Sprintf("MGTLS_RENEWED_CERTS=%s", strings.Join(rep.RenewedCerts, ",")),
			)
			out, err := cmd.CombinedOutput()
			rep.HookExecuted = true
			rep.HookOutput = strings.TrimSpace(string(out))
			if err != nil {
				errs = append(errs, fmt.Errorf("on-renew hook failed: %w (output: %s)", err, rep.HookOutput))
			}
		}
	}

	for _, e := range errs {
		rep.Errors = append(rep.Errors, e.Error())
	}
	return rep, errors.Join(errs...)
}

// Watch runs RunRenewalCycle immediately and then every opts.Interval until ctx is canceled (or returns after 1 pass when opts.Once is true).
func Watch(ctx context.Context, s *store.Store, opts WatchOptions, onCycle func(*RenewalCycleReport)) error {
	if s == nil {
		return errors.New("store is nil")
	}
	var spec *FleetSpec
	if strings.TrimSpace(opts.ManifestPath) != "" {
		loaded, err := LoadFleetSpec(opts.ManifestPath)
		if err != nil {
			return err
		}
		spec = loaded
	}
	rep, err := RunRenewalCycle(ctx, s, spec, opts.RenewBefore, opts.OnRenewHook)
	if onCycle != nil && rep != nil {
		onCycle(rep)
	}
	if opts.Once {
		return err
	}
	// A daemon must survive transient failures (CA outage, network); errors are
	// reported through onCycle and retried on the next tick. Only setup errors
	// (no report at all) are fatal.
	if err != nil && rep == nil {
		return err
	}

	interval := opts.Interval
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			var reloadErr error
			if strings.TrimSpace(opts.ManifestPath) != "" {
				if reloaded, lErr := LoadFleetSpec(opts.ManifestPath); lErr == nil {
					spec = reloaded
				} else {
					reloadErr = fmt.Errorf("reload manifest (keeping previous spec): %w", lErr)
				}
			}
			cycleRep, cycleErr := RunRenewalCycle(ctx, s, spec, opts.RenewBefore, opts.OnRenewHook)
			if cycleRep == nil {
				cycleRep = &RenewalCycleReport{CheckedAt: time.Now().UTC()}
				if cycleErr != nil {
					cycleRep.Errors = append(cycleRep.Errors, cycleErr.Error())
				}
			}
			if reloadErr != nil {
				cycleRep.Errors = append([]string{reloadErr.Error()}, cycleRep.Errors...)
			}
			if onCycle != nil {
				onCycle(cycleRep)
			}
		}
	}
}

// GenerateSystemdUnits writes a systemd .service and .timer unit pair for unattended certificate renewal.
func GenerateSystemdUnits(s *store.Store, req SystemdRequest) (*SystemdBundle, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	unitName := strings.TrimSpace(req.UnitName)
	if unitName == "" {
		unitName = "mgtls-renew"
	}
	binPath := strings.TrimSpace(req.BinaryPath)
	if binPath == "" {
		binPath = "/usr/local/bin/mgtls"
	}
	storeDir := strings.TrimSpace(req.StoreDir)
	if storeDir == "" {
		storeDir = s.BaseDir
	}
	calendar := strings.TrimSpace(req.Calendar)
	if calendar == "" {
		calendar = "*-*-* 00,12:00:00"
	}
	renewBefore := strings.TrimSpace(req.RenewBefore)
	if renewBefore == "" {
		renewBefore = "720h"
	}
	outDir := strings.TrimSpace(req.OutputDir)
	if outDir == "" {
		outDir = s.Path("systemd")
	} else {
		abs, err := filepath.Abs(outDir)
		if err != nil {
			return nil, fmt.Errorf("resolve systemd output dir: %w", err)
		}
		outDir = abs
	}
	if err := store.ValidName("systemd unit", unitName); err != nil {
		return nil, err
	}
	if !systemdCalendarRE.MatchString(calendar) {
		return nil, fmt.Errorf("invalid OnCalendar value %q", calendar)
	}
	if d, err := time.ParseDuration(renewBefore); err != nil || d <= 0 {
		return nil, fmt.Errorf("invalid renew-before duration %q", renewBefore)
	}
	for field, v := range map[string]string{"binary path": binPath, "store dir": storeDir, "manifest path": req.ManifestPath, "on-renew hook": req.OnRenewHook, "output dir": outDir} {
		if strings.ContainsAny(v, "\x00\r\n") {
			return nil, fmt.Errorf("%s must not contain newlines or NUL (would inject unit directives)", field)
		}
	}
	if !filepath.IsAbs(binPath) {
		return nil, fmt.Errorf("binary path %q must be absolute for systemd ExecStart", binPath)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir systemd output dir: %w", err)
	}

	args := []string{binPath, "--store-dir", storeDir, "watch", "--once", "--renew-before", renewBefore}
	if strings.TrimSpace(req.ManifestPath) != "" {
		args = append(args, "-f", req.ManifestPath)
	}
	if strings.TrimSpace(req.OnRenewHook) != "" {
		args = append(args, "--on-renew", req.OnRenewHook)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = systemdQuote(a)
	}
	execCmd := strings.Join(quoted, " ")

	serviceContent := fmt.Sprintf(`[Unit]
Description=mgtls Autonomous Certificate & Target Renewal (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
`, unitName, execCmd)

	timerContent := fmt.Sprintf(`[Unit]
Description=mgtls Autonomous Certificate Renewal Timer (%s)

[Timer]
OnCalendar=%s
RandomizedDelaySec=5m
Persistent=true
Unit=%s.service

[Install]
WantedBy=timers.target
`, unitName, calendar, unitName)

	servicePath := filepath.Join(outDir, unitName+".service")
	timerPath := filepath.Join(outDir, unitName+".timer")

	if err := store.WriteFileAtomic(servicePath, []byte(serviceContent), 0644); err != nil {
		return nil, fmt.Errorf("write %s: %w", servicePath, err)
	}
	if err := store.WriteFileAtomic(timerPath, []byte(timerContent), 0644); err != nil {
		return nil, fmt.Errorf("write %s: %w", timerPath, err)
	}

	installCmds := []string{
		fmt.Sprintf("sudo cp -- %s %s /etc/systemd/system/", pki.ShellQuote(servicePath), pki.ShellQuote(timerPath)),
		fmt.Sprintf("sudo systemctl daemon-reload && sudo systemctl enable --now %s.timer", unitName),
	}

	return &SystemdBundle{
		ServicePath: servicePath,
		TimerPath:   timerPath,
		InstallCmds: installCmds,
	}, nil
}

var systemdCalendarRE = regexp.MustCompile(`^[A-Za-z0-9 ,:*./~+-]{1,128}$`)

// systemdQuote renders one ExecStart argument. systemd parses double-quoted words
// with C-style backslash escapes and still expands %-specifiers and $VARS inside
// quotes, so those are doubled to stay literal. Go's %q is not equivalent.
func systemdQuote(a string) string {
	a = strings.ReplaceAll(a, `\`, `\\`)
	a = strings.ReplaceAll(a, `"`, `\"`)
	a = strings.ReplaceAll(a, "%", "%%")
	a = strings.ReplaceAll(a, "$", "$$")
	return `"` + a + `"`
}

type yamlLine struct {
	lineNum int
	indent  int
	text    string
}

func parseYAMLToObject(input string) (any, error) {
	rawLines := strings.Split(input, "\n")
	var lines []yamlLine
	for idx, raw := range rawLines {
		cleaned := stripYAMLComment(raw)
		trimmed := strings.TrimSpace(cleaned)
		if trimmed == "" || trimmed == "---" || trimmed == "..." {
			continue
		}
		indent := 0
		for _, ch := range cleaned {
			if ch == ' ' {
				indent++
			} else if ch == '\t' {
				indent += 2
			} else {
				break
			}
		}
		lines = append(lines, yamlLine{
			lineNum: idx + 1,
			indent:  indent,
			text:    trimmed,
		})
	}
	if len(lines) == 0 {
		return nil, errors.New("no YAML content found")
	}
	pos := 0
	return parseYAMLNode(lines, &pos, lines[0].indent)
}

func stripYAMLComment(s string) string {
	var inSingle, inDouble bool
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && inDouble {
			i++
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if ch == '#' && !inSingle && !inDouble {
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

func isYAMLSeqLine(l yamlLine) bool {
	return l.text == "-" || strings.HasPrefix(l.text, "- ")
}

func parseYAMLNode(lines []yamlLine, pos *int, minIndent int) (any, error) {
	if *pos >= len(lines) {
		return nil, nil
	}
	if isYAMLSeqLine(lines[*pos]) {
		return parseYAMLSequence(lines, pos, lines[*pos].indent)
	}
	return parseYAMLMap(lines, pos, minIndent)
}

func parseYAMLMap(lines []yamlLine, pos *int, minIndent int) (map[string]any, error) {
	m := make(map[string]any)
	for *pos < len(lines) {
		l := lines[*pos]
		if l.indent < minIndent || isYAMLSeqLine(l) {
			break
		}
		key, valStr, ok := splitYAMLKeyValue(l.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected key: value, got %q", l.lineNum, l.text)
		}
		*pos++
		val, err := resolveYAMLValue(lines, pos, l.indent, valStr)
		if err != nil {
			return nil, err
		}
		m[unquoteYAMLString(key)] = val
	}
	return m, nil
}

func resolveYAMLValue(lines []yamlLine, pos *int, keyIndent int, valStr string) (any, error) {
	if valStr != "" {
		return parseYAMLScalarOrFlow(valStr), nil
	}
	if *pos >= len(lines) {
		return nil, nil
	}
	next := lines[*pos]
	if next.indent > keyIndent {
		return parseYAMLNode(lines, pos, next.indent)
	}
	if next.indent == keyIndent && isYAMLSeqLine(next) {
		return parseYAMLSequence(lines, pos, next.indent)
	}
	return nil, nil
}

func parseYAMLSequence(lines []yamlLine, pos *int, seqIndent int) ([]any, error) {
	var seq []any
	for *pos < len(lines) {
		l := lines[*pos]
		if l.indent != seqIndent || !isYAMLSeqLine(l) {
			break
		}
		*pos++
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		if rest == "" {
			if *pos < len(lines) && lines[*pos].indent > seqIndent {
				item, err := parseYAMLNode(lines, pos, lines[*pos].indent)
				if err != nil {
					return nil, err
				}
				seq = append(seq, item)
			} else {
				seq = append(seq, nil)
			}
			continue
		}

		if key, valStr, ok := splitYAMLKeyValue(rest); ok && !strings.HasPrefix(rest, "{") && !strings.HasPrefix(rest, "[") {
			itemMap := make(map[string]any)
			firstVal, err := resolveYAMLValue(lines, pos, seqIndent+2, valStr)
			if err != nil {
				return nil, err
			}
			itemMap[unquoteYAMLString(key)] = firstVal

			for *pos < len(lines) && lines[*pos].indent > seqIndent {
				sub := lines[*pos]
				if isYAMLSeqLine(sub) {
					break
				}
				k, vStr, ok := splitYAMLKeyValue(sub.text)
				if !ok {
					return nil, fmt.Errorf("line %d: expected key: value in sequence map, got %q", sub.lineNum, sub.text)
				}
				*pos++
				v, err := resolveYAMLValue(lines, pos, sub.indent, vStr)
				if err != nil {
					return nil, err
				}
				itemMap[unquoteYAMLString(k)] = v
			}
			seq = append(seq, itemMap)
			continue
		}

		seq = append(seq, parseYAMLScalarOrFlow(rest))
	}
	return seq, nil
}

func splitYAMLKeyValue(s string) (string, string, bool) {
	var inSingle, inDouble bool
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && inDouble {
			i++
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if ch == ':' && !inSingle && !inDouble {
			if i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
				k := strings.TrimSpace(s[:i])
				v := strings.TrimSpace(s[i+1:])
				return k, v, k != ""
			}
		}
	}
	return "", "", false
}

func parseYAMLScalarOrFlow(s string) any {
	s = strings.TrimSpace(s)
	if s == "" || s == "~" || s == "null" || s == "NULL" {
		return nil
	}
	if s == "[]" {
		return []any{}
	}
	if s == "{}" {
		return map[string]any{}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		var arr []any
		if err := json.Unmarshal([]byte(s), &arr); err == nil {
			return arr
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}
		}
		parts := splitTopLevelComma(inner)
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			out = append(out, parseYAMLScalarOrFlow(p))
		}
		return out
	}
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(s), &obj); err == nil {
			return obj
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		out := make(map[string]any)
		if inner == "" {
			return out
		}
		for _, p := range splitTopLevelComma(inner) {
			if k, v, ok := splitYAMLKeyValue(p); ok {
				out[unquoteYAMLString(k)] = parseYAMLScalarOrFlow(v)
			}
		}
		return out
	}
	if (strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"")) ||
		(strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")) {
		return unquoteYAMLString(s)
	}
	if s == "true" || s == "True" || s == "TRUE" {
		return true
	}
	if s == "false" || s == "False" || s == "FALSE" {
		return false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return s
}

func splitTopLevelComma(s string) []string {
	var parts []string
	var inSingle, inDouble bool
	start := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && inDouble {
			i++
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if ch == ',' && !inSingle && !inDouble {
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}

func unquoteYAMLString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
			if unq, err := strconv.Unquote(s); err == nil {
				return unq
			}
			return s[1 : len(s)-1]
		}
		if strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") {
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		}
	}
	return s
}
