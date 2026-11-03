package targets

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/store"
)

// TargetSpec describes a supported target platform integration bundle.
type TargetSpec struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"` // api, ai-agent, proxy, frontend, virtualization, ssh
	Description string   `json:"description"`
	Files       []string `json:"files"`
}

// GenerateRequest configures target integration artifact generation.
type GenerateRequest struct {
	Name           string            `json:"name" yaml:"name"`
	TargetType     string            `json:"target_type" yaml:"target_type"` // fastapi, springboot, mcp, nginx, vite, proxmox, openssh
	OutputDir      string            `json:"output_dir,omitempty" yaml:"output_dir,omitempty"`
	Host           string            `json:"host,omitempty" yaml:"host,omitempty"` // default "localhost"
	Port           int               `json:"port,omitempty" yaml:"port,omitempty"` // default per target
	MutualTLS      bool              `json:"mutual_tls" yaml:"mutual_tls"`         // true = strict mTLS
	CAName         string            `json:"ca_name,omitempty" yaml:"ca_name,omitempty"`
	CACertPath     string            `json:"ca_cert_path" yaml:"ca_cert_path"`
	ServerCert     string            `json:"server_cert,omitempty" yaml:"server_cert,omitempty"`
	ServerCertPath string            `json:"server_cert_path" yaml:"server_cert_path"`
	ServerKeyPath  string            `json:"server_key_path" yaml:"server_key_path"`
	ClientCert     string            `json:"client_cert,omitempty" yaml:"client_cert,omitempty"`
	ClientCertPath string            `json:"client_cert_path" yaml:"client_cert_path"`
	ClientKeyPath  string            `json:"client_key_path" yaml:"client_key_path"`
	Extra          map[string]string `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// GenerateResult returns the persisted target record and operational notes.
type GenerateResult struct {
	Record store.TargetRecord `json:"record"`
	Notes  []string           `json:"notes"`
}

// SupportedTargets returns specifications for all 7 supported target integrations.
func SupportedTargets() []TargetSpec {
	return []TargetSpec{
		{
			ID:          "fastapi",
			Name:        "Python FastAPI + Uvicorn",
			Category:    "api",
			Description: "Python FastAPI + Uvicorn TLS 1.3 & mTLS server, httpx client, and verification script",
			Files:       []string{"app.py", "run_server.sh", "client_mtls.py", "verify_mtls.sh"},
		},
		{
			ID:          "springboot",
			Name:        "Spring Boot 3 REST API",
			Category:    "api",
			Description: "Spring Boot 3 SSL/mTLS PEM bundle configuration, Spring Security x509 filter, and RestClient",
			Files:       []string{"application-tls.yml", "MtlsSecurityConfig.java", "MtlsRestClientConfig.java", "verify_mtls.sh"},
		},
		{
			ID:          "mcp",
			Name:        "Model Context Protocol (MCP) Server & Client",
			Category:    "ai-agent",
			Description: "MCP Server & Client mTLS setup for TypeScript, Python, NGINX sidecar, and Claude/Cursor JSON config",
			Files:       []string{"mcp_server_mtls.ts", "mcp_server_mtls.py", "mcp_client_config.json", "nginx_mcp_sidecar.conf", "verify_mcp_mtls.sh"},
		},
		{
			ID:          "nginx",
			Name:        "NGINX TLS 1.3 & mTLS Reverse Proxy",
			Category:    "proxy",
			Description: "Hardened NGINX TLS 1.2/1.3 & mutual TLS reverse proxy configuration with identity forwarding headers",
			Files:       []string{"nginx-mtls.conf", "verify_nginx_mtls.sh"},
		},
		{
			ID:          "vite",
			Name:        "Vite Dev/Preview HTTPS & mTLS Server",
			Category:    "frontend",
			Description: "Vite node:https dev/preview server configuration with client certificate verification and Node.js undici client",
			Files:       []string{"vite.config.mtls.ts", "client_fetch_mtls.mjs"},
		},
		{
			ID:          "proxmox",
			Name:        "Proxmox VE Node TLS/mTLS & ACME Deployment",
			Category:    "virtualization",
			Description: "Proxmox VE pveproxy certificate installation script, API verification tool, and operational guide",
			Files:       []string{"deploy_proxmox_cert.sh", "proxmox_pveproxy_verify.sh", "README-proxmox.md"},
		},
		{
			ID:          "openssh",
			Name:        "OpenSSH Server & Client CA Setup",
			Category:    "ssh",
			Description: "OpenSSH TrustedUserCAKeys, HostCertificate, @cert-authority known_hosts, and deployment script",
			Files:       []string{"sshd_ca.conf", "ssh_client_ca.conf", "deploy_ssh_ca.sh"},
		},
	}
}

func defaultPortForTarget(targetType string) int {
	switch targetType {
	case "fastapi":
		return 8443
	case "springboot":
		return 8443
	case "mcp":
		return 8444
	case "nginx":
		return 443
	case "vite":
		return 5173
	case "proxmox":
		return 8006
	case "openssh":
		return 22
	default:
		return 8443
	}
}

type templateContext struct {
	Name                string
	TargetType          string
	OutputDir           string
	Host                string
	Port                int
	MutualTLS           bool
	CAName              string
	CACertPath          string
	ServerCert          string
	ServerCertPath      string
	ServerKeyPath       string
	ClientCert          string
	ClientCertPath      string
	ClientKeyPath       string
	LocalCACertPath     string
	LocalServerCertPath string
	LocalServerKeyPath  string
	LocalClientCertPath string
	LocalClientKeyPath  string
	Extra               map[string]string
}

// Generate validates the request, bundles certificate material, renders target configuration files, and updates the store manifest.
func Generate(s *store.Store, req GenerateRequest) (*GenerateResult, error) {
	if s == nil {
		return nil, fmt.Errorf("store cannot be nil")
	}
	targetType := strings.ToLower(strings.TrimSpace(req.TargetType))
	var spec *TargetSpec
	for _, sp := range SupportedTargets() {
		if sp.ID == targetType {
			cp := sp
			spec = &cp
			break
		}
	}
	if spec == nil {
		return nil, fmt.Errorf("unsupported target type %q", req.TargetType)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = targetType
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = "localhost"
	}
	port := req.Port
	if port <= 0 {
		port = defaultPortForTarget(targetType)
	}

	outDir := strings.TrimSpace(req.OutputDir)
	if outDir == "" {
		outDir = s.Path("targets", name)
	} else {
		abs, err := filepath.Abs(outDir)
		if err != nil {
			return nil, fmt.Errorf("resolve output dir: %w", err)
		}
		outDir = abs
	}

	certsDir := filepath.Join(outDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("create target certs dir: %w", err)
	}

	caCertPath := req.CACertPath
	if caCertPath == "" {
		caCertPath = filepath.Join(certsDir, "ca.crt")
	}
	serverCertPath := req.ServerCertPath
	if serverCertPath == "" {
		serverCertPath = filepath.Join(certsDir, "server.crt")
	}
	serverKeyPath := req.ServerKeyPath
	if serverKeyPath == "" {
		serverKeyPath = filepath.Join(certsDir, "server.key")
	}
	clientCertPath := req.ClientCertPath
	if clientCertPath == "" {
		clientCertPath = filepath.Join(certsDir, "client.crt")
	}
	clientKeyPath := req.ClientKeyPath
	if clientKeyPath == "" {
		clientKeyPath = filepath.Join(certsDir, "client.key")
	}

	localCACert := copyArtifactIfPresent(req.CACertPath, filepath.Join(certsDir, "ca.crt"), 0644, caCertPath)
	localServerCert := copyArtifactIfPresent(req.ServerCertPath, filepath.Join(certsDir, "server.crt"), 0644, serverCertPath)
	localServerKey := copyArtifactIfPresent(req.ServerKeyPath, filepath.Join(certsDir, "server.key"), 0600, serverKeyPath)
	localClientCert := copyArtifactIfPresent(req.ClientCertPath, filepath.Join(certsDir, "client.crt"), 0644, clientCertPath)
	localClientKey := copyArtifactIfPresent(req.ClientKeyPath, filepath.Join(certsDir, "client.key"), 0600, clientKeyPath)

	extra := make(map[string]string, len(req.Extra))
	for k, v := range req.Extra {
		extra[k] = v
	}
	if extra["upstream_url"] == "" {
		extra["upstream_url"] = "http://127.0.0.1:8000"
	}

	ctx := templateContext{
		Name:                name,
		TargetType:          targetType,
		OutputDir:           outDir,
		Host:                host,
		Port:                port,
		MutualTLS:           req.MutualTLS,
		CAName:              req.CAName,
		CACertPath:          caCertPath,
		ServerCert:          req.ServerCert,
		ServerCertPath:      serverCertPath,
		ServerKeyPath:       serverKeyPath,
		ClientCert:          req.ClientCert,
		ClientCertPath:      clientCertPath,
		ClientKeyPath:       clientKeyPath,
		LocalCACertPath:     localCACert,
		LocalServerCertPath: localServerCert,
		LocalServerKeyPath:  localServerKey,
		LocalClientCertPath: localClientCert,
		LocalClientKeyPath:  localClientKey,
		Extra:               extra,
	}

	tmplMap, ok := targetTemplates[targetType]
	if !ok {
		return nil, fmt.Errorf("missing templates for target %q", targetType)
	}

	var writtenFiles []string
	for _, filename := range spec.Files {
		rawTmpl, exists := tmplMap[filename]
		if !exists {
			return nil, fmt.Errorf("missing template %s for target %s", filename, targetType)
		}
		rendered, err := renderTemplate(filename, rawTmpl, ctx)
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", filename, err)
		}
		destPath := filepath.Join(outDir, filename)
		perm := os.FileMode(0644)
		if strings.HasSuffix(filename, ".sh") {
			perm = 0755
		}
		if err := os.WriteFile(destPath, rendered, perm); err != nil {
			return nil, fmt.Errorf("write %s: %w", destPath, err)
		}
		if err := os.Chmod(destPath, perm); err != nil {
			return nil, fmt.Errorf("chmod %s: %w", destPath, err)
		}
		writtenFiles = append(writtenFiles, destPath)
	}

	rec := store.TargetRecord{
		Name:       name,
		TargetType: targetType,
		OutputDir:  outDir,
		CAName:     req.CAName,
		ServerCert: req.ServerCert,
		ClientCert: req.ClientCert,
		Files:      writtenFiles,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.UpsertTarget(rec); err != nil {
		return nil, fmt.Errorf("record target in manifest: %w", err)
	}

	notes := []string{
		fmt.Sprintf("Target %q (%s) generated in %s", name, spec.Name, outDir),
		fmt.Sprintf("Endpoint configured for %s:%d (mTLS=%v)", host, port, req.MutualTLS),
	}
	return &GenerateResult{
		Record: rec,
		Notes:  notes,
	}, nil
}

func copyArtifactIfPresent(srcPath, dstPath string, mode os.FileMode, fallback string) string {
	if strings.TrimSpace(srcPath) == "" {
		return fallback
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fallback
	}
	if err := os.WriteFile(dstPath, data, mode); err != nil {
		return fallback
	}
	_ = os.Chmod(dstPath, mode)
	return dstPath
}

func renderTemplate(name, raw string, ctx templateContext) ([]byte, error) {
	t, err := template.New(name).Parse(raw)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
