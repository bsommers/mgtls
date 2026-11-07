package targets

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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

// SupportedTargets returns specifications for all 14 supported target integrations.
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
		{
			ID:          "caddy",
			Name:        "Caddy 2 TLS 1.3 & Mutual TLS Reverse Proxy",
			Category:    "proxy",
			Description: "Caddyfile with strict client_auth mTLS verification and upstream identity header injection",
			Files:       []string{"Caddyfile", "verify_caddy_mtls.sh"},
		},
		{
			ID:          "traefik",
			Name:        "Traefik v3 Dynamic TLS & mTLS Router",
			Category:    "proxy",
			Description: "Traefik v3 dynamic TLS options (RequireAndVerifyClientCert) and HTTP router configuration",
			Files:       []string{"traefik-dynamic-tls.yml", "verify_traefik_mtls.sh"},
		},
		{
			ID:          "envoy",
			Name:        "Envoy Proxy Downstream mTLS & SPIFFE Validator",
			Category:    "proxy",
			Description: "Envoy static bootstrap with DownstreamTlsContext client certificate & SAN validation",
			Files:       []string{"envoy-mtls.yaml", "verify_envoy_mtls.sh"},
		},
		{
			ID:          "postgres",
			Name:        "PostgreSQL 16+ Server & Client mTLS (verify-full)",
			Category:    "database",
			Description: "PostgreSQL postgresql.conf SSL settings, pg_hba.conf clientcert=verify-full rules, and psql client verification script",
			Files:       []string{"postgresql-ssl.conf", "pg_hba_mtls.conf", "verify_postgres_mtls.sh"},
		},
		{
			ID:          "redis",
			Name:        "Redis 7+ / Valkey TLS & Mutual TLS Server",
			Category:    "database",
			Description: "Redis TLS configuration (tls-auth-clients) and redis-cli mTLS ping verification script",
			Files:       []string{"redis-tls.conf", "verify_redis_mtls.sh"},
		},
		{
			ID:          "grpc-go",
			Name:        "Go gRPC TLS 1.3 & Mutual TLS Server/Client",
			Category:    "api",
			Description: "Go google.golang.org/grpc/credentials TLS 1.3 mutual authentication server and client starter",
			Files:       []string{"grpc_mtls.go", "verify_grpc_mtls.sh"},
		},
		{
			ID:          "nodejs-express",
			Name:        "Node.js HTTPS / Express Mutual TLS Server & Client",
			Category:    "api",
			Description: "Node.js node:https server with peer certificate inspection and mTLS client verification script",
			Files:       []string{"server_mtls.mjs", "verify_node_mtls.sh"},
		},
	}
}

func defaultPortForTarget(targetType string) int {
	switch targetType {
	case "fastapi", "springboot":
		return 8443
	case "mcp":
		return 8444
	case "nginx", "caddy", "traefik":
		return 443
	case "envoy":
		return 10000
	case "vite":
		return 5173
	case "proxmox":
		return 8006
	case "openssh":
		return 22
	case "postgres":
		return 5432
	case "redis":
		return 6379
	case "grpc-go":
		return 50051
	case "nodejs-express":
		return 3443
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
	if err := store.ValidName("target", name); err != nil {
		return nil, err
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

	if err := validateRenderInputs(host, port, outDir, req); err != nil {
		return nil, err
	}

	certsDir := filepath.Join(outDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
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

	var copyErrs []error
	cp := func(src, dst string, mode os.FileMode, fallback string) string {
		out, err := copyArtifactIfPresent(src, dst, mode, fallback)
		if err != nil {
			copyErrs = append(copyErrs, err)
		}
		return out
	}
	localCACert := cp(req.CACertPath, filepath.Join(certsDir, "ca.crt"), 0644, caCertPath)
	localServerCert := cp(req.ServerCertPath, filepath.Join(certsDir, "server.crt"), 0644, serverCertPath)
	localServerKey := cp(req.ServerKeyPath, filepath.Join(certsDir, "server.key"), 0600, serverKeyPath)
	localClientCert := cp(req.ClientCertPath, filepath.Join(certsDir, "client.crt"), 0644, clientCertPath)
	localClientKey := cp(req.ClientKeyPath, filepath.Join(certsDir, "client.key"), 0600, clientKeyPath)
	if err := errors.Join(copyErrs...); err != nil {
		// Previously swallowed: the bundle would reference files that were never written.
		return nil, err
	}

	extra := make(map[string]string, len(req.Extra))
	for k, v := range req.Extra {
		extra[k] = v
	}
	if extra["upstream_url"] == "" {
		extra["upstream_url"] = "http://127.0.0.1:8000"
	}
	for k, v := range extra {
		if err := checkConfigValue("extra."+k, v); err != nil {
			return nil, err
		}
	}
	if u, err := url.Parse(extra["upstream_url"]); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("extra.upstream_url %q must be an absolute http(s) URL", extra["upstream_url"])
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
		if err := store.WriteFileAtomic(destPath, rendered, perm); err != nil {
			return nil, fmt.Errorf("write %s: %w", destPath, err)
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

// copyArtifactIfPresent copies srcPath into the bundle when it exists locally. An empty
// or locally absent srcPath returns fallback (the path is then referenced verbatim, e.g.
// a path on the deployment host). Any other read error, or a write error, is returned
// instead of being swallowed.
func copyArtifactIfPresent(srcPath, dstPath string, mode os.FileMode, fallback string) (string, error) {
	if strings.TrimSpace(srcPath) == "" {
		return fallback, nil
	}
	data, err := os.ReadFile(srcPath)
	if errors.Is(err, fs.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return "", fmt.Errorf("read artifact %s: %w", srcPath, err)
	}
	if err := store.WriteFileAtomic(dstPath, data, mode); err != nil {
		return "", fmt.Errorf("write artifact %s: %w", dstPath, err)
	}
	return dstPath, nil
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9.:_\[\]-]{1,253}$`)

// checkConfigValue rejects characters that let a value escape its slot in any of the
// generated formats (shell scripts, nginx/Caddy/sshd directives, YAML, JSON, TS, Java):
// control characters (newline ends a comment or directive), quotes, backslash, shell
// expansion ($ and backtick) and directive/block delimiters.
func checkConfigValue(field, v string) error {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	if strings.ContainsAny(v, "\"'`$\\;{}") {
		return fmt.Errorf("%s %q contains a forbidden character (one of \" ' ` $ \\ ; { })", field, v)
	}
	return nil
}

func validateRenderInputs(host string, port int, outDir string, req GenerateRequest) error {
	if !hostRE.MatchString(host) {
		return fmt.Errorf("invalid host %q: expected a hostname or IP address", host)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
	for field, v := range map[string]string{
		"output_dir":       outDir,
		"ca_cert_path":     req.CACertPath,
		"server_cert_path": req.ServerCertPath,
		"server_key_path":  req.ServerKeyPath,
		"client_cert_path": req.ClientCertPath,
		"client_key_path":  req.ClientKeyPath,
		"ca_name":          req.CAName,
		"server_cert":      req.ServerCert,
		"client_cert":      req.ClientCert,
	} {
		if err := checkConfigValue(field, v); err != nil {
			return err
		}
	}
	return nil
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
