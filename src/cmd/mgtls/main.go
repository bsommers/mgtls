package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/acme"
	"github.com/sysadmin/mgtls/src/pkg/mcpserver"
	"github.com/sysadmin/mgtls/src/pkg/pki"
	"github.com/sysadmin/mgtls/src/pkg/profile"
	"github.com/sysadmin/mgtls/src/pkg/sshca"
	"github.com/sysadmin/mgtls/src/pkg/store"
	"github.com/sysadmin/mgtls/src/pkg/targets"
)

const Version = "1.2.0"

func main() {
	// Cancel on SIGINT/SIGTERM so `mgtls watch` and `mgtls mcp serve` shut down
	// between cycles instead of being killed mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	storeDir := os.Getenv("MGTLS_STORE_DIR")
	if storeDir == "" {
		storeDir = ".mgtls"
	}

	// Extract global --store-dir if passed before subcommand.
	for len(args) >= 2 && (args[0] == "--store-dir" || args[0] == "-s") {
		storeDir = args[1]
		args = args[2:]
	}
	if len(args) >= 1 && strings.HasPrefix(args[0], "--store-dir=") {
		storeDir = strings.TrimPrefix(args[0], "--store-dir=")
		args = args[1:]
	}

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stdout)
		return nil
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "mgtls version %s\n", Version)
		return nil
	case "guide":
		printGuide(stdout)
		return nil
	case "init":
		return runInit(storeDir, rest, stdout, stderr)
	case "ca":
		return runCA(storeDir, rest, stdout)
	case "cert":
		return runCert(storeDir, rest, stdout)
	case "ssh":
		return runSSH(storeDir, rest, stdout)
	case "acme":
		return runACME(ctx, storeDir, rest, stdout)
	case "target":
		return runTarget(storeDir, rest, stdout)
	case "apply":
		return runApply(ctx, storeDir, rest, stdout, stderr)
	case "status":
		return runStatus(storeDir, rest, stdout)
	case "doctor":
		return runDoctor(storeDir, rest, stdout, stderr)
	case "watch":
		return runWatch(ctx, storeDir, rest, stdout)
	case "systemd":
		return runSystemd(storeDir, rest, stdout)
	case "probe":
		return runProbe(storeDir, rest, stdout)
	case "ocsp":
		return runOCSP(ctx, storeDir, rest, stdout)
	case "mcp":
		return runMCP(ctx, storeDir, rest, stdin, stdout)
	default:
		return fmt.Errorf("unknown command %q (run 'mgtls --help' or 'mgtls guide' for usage)", cmd)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `mgtls v%s — Unified TLS, mTLS, Local/Public CA, OpenSSH CA & Target Provisioning Engine (CLI + MCP)

Usage:
  mgtls [--store-dir <dir>] <command> [subcommand] [flags]

Commands:
  init                       Initialize cryptographic workspace store (and optional Root/Intermediate CA)
  ca <subcommand>            Manage X.509 Root & Intermediate Certificate Authorities
    create                   Create a Root CA or Intermediate CA
    list                     List managed CAs
    trust-script             Generate OS trust store installation scripts
  cert <subcommand>          Manage X.509 Server, Client, mTLS, and Self-Signed certificates
    issue                    Issue a leaf certificate signed by a CA
    self-sign                Create a standalone self-signed certificate
    inspect                  Inspect an X.509 certificate
    verify                   Verify a certificate chain, SANs, role, and CRL
    revoke                   Revoke a certificate and update the CA's CRL
  ssh <subcommand>           Manage OpenSSH User & Host CAs and certificates
    ca-create                Create an OpenSSH User or Host CA
    sign-user                Sign an OpenSSH User certificate
    sign-host                Sign an OpenSSH Host certificate
    inspect                  Inspect an OpenSSH *-cert.pub certificate
    config                   Generate sshd_config, ssh_config, known_hosts & per-account auth_principals/
  acme <subcommand>          Manage free public TLS certificates via ACME v2 (Let's Encrypt, ZeroSSL, Buypass, Google)
    providers                List built-in public ACME v2 providers
    obtain                   Obtain a certificate via HTTP-01, TLS-ALPN-01, or DNS-01
    renew-check              Check ACME certificates approaching expiration
  target <subcommand>        Scaffold production TLS/mTLS setups for servers & frameworks
    list                     List supported targets (fastapi, springboot, mcp, nginx, vite, proxmox, openssh, caddy, traefik, envoy, postgres, redis, grpc-go, nodejs-express)
    generate                 Generate a complete target bundle (auto-provisions certs if needed)
  apply -f <mgtls.yaml>      Declaratively provision an entire PKI/SSH/ACME/Target fleet from YAML/JSON
  status                     Display store inventory manifest
  doctor                     Audit store health, key permissions, and certificate expirations
  watch                      Autonomous renewal loop (monitors expirations, re-issues certs, runs --on-renew hooks)
  systemd generate           Generate systemd .service & .timer units for unattended renewal
  probe                      Probe a live TLS/mTLS endpoint (protocol, cipher suite, peer chain, SANs & CA trust)
  ocsp <serve|verify>        RFC 6960 HTTP OCSP responder & certificate/stapling verifier
  mcp serve                  Run the Model Context Protocol (MCP) JSON-RPC 2.0 server (stdio or HTTP/mTLS)
  guide                      View the full end-to-end onboarding & workflow guide
  version                    Print version

Quickstart (Install -> Init -> Verify -> Run):
  1. mgtls init --with-root-ca --starter
  2. mgtls doctor
  3. mgtls apply -f mgtls.yaml
  4. mgtls guide
`, Version)
}

func printGuide(w io.Writer) {
	fmt.Fprintf(w, `mgtls v%s — Onboarding & End-to-End Workflow Guide

1. INITIALIZE WORKSPACE & ROOT CA
   mgtls init --with-root-ca --starter
   # Creates .mgtls/ store (0700 dirs, 0600 keys), Root CA, and starter mgtls.yaml

2. AUDIT HEALTH & KEY PERMISSIONS
   mgtls doctor
   # Verifies manifest integrity, 0600 key permissions, and certificate expirations

3. RECONCILE DECLARATIVE FLEET OR GENERATE TARGET BUNDLES
   mgtls apply -f mgtls.yaml
   mgtls target generate --type fastapi --name api-mtls --host api.internal --mtls --out ./fastapi-bundle
   # Supported targets (14): fastapi, springboot, mcp, nginx, vite, proxmox, openssh,
   #                         caddy, traefik, envoy, postgres, redis, grpc-go, nodejs-express

4. ISSUE OPENSSH CAs & PUBLIC ACME v2 CERTIFICATES
   mgtls ssh ca-create --name ssh-user-ca --type user
   mgtls acme providers
   mgtls acme obtain --provider letsencrypt-staging --email sec@example.com --domains example.com

5. RUN MODEL CONTEXT PROTOCOL (MCP) SERVER FOR AI AGENTS
   mgtls mcp serve --transport stdio
   mgtls mcp serve --transport http --addr 127.0.0.1:8443 --tls-cert cert.pem --tls-key key.pem --client-ca ca.pem
`, Version)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// accountFlag collects repeatable --account ACCOUNT=P1,P2 values.
type accountFlag struct{ m map[string][]string }

func (a *accountFlag) String() string { return fmt.Sprint(a.m) }

func (a *accountFlag) Set(v string) error {
	acct, ps, ok := strings.Cut(v, "=")
	acct = strings.TrimSpace(acct)
	if !ok || acct == "" || len(splitCSV(ps)) == 0 {
		return fmt.Errorf("expected ACCOUNT=PRINCIPAL[,PRINCIPAL...], got %q", v)
	}
	if a.m == nil {
		a.m = map[string][]string{}
	}
	a.m[acct] = append(a.m[acct], splitCSV(ps)...)
	return nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

const starterManifestYAML = `# mgtls.yaml — Declarative PKI, mTLS, OpenSSH CA & Target Fleet Manifest
store_dir: .mgtls

cas:
  - name: root-ca
    common_name: "mgtls Local Root CA"
    algorithm: ed25519
    valid_days: 3650

certs:
  - name: api-server
    common_name: localhost
    ca_name: root-ca
    role: mtls
    algorithm: ed25519
    dns_names: [localhost, api.internal]
    ip_addresses: [127.0.0.1]

  - name: api-client
    common_name: api-client
    ca_name: root-ca
    role: client
    algorithm: ed25519
`

func runInit(defaultStoreDir string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	withRoot := fs.Bool("with-root-ca", false, "Also create a default Root CA")
	rootName := fs.String("root-name", "root-ca", "Root CA name")
	rootCN := fs.String("root-cn", "mgtls Local Root CA", "Root CA Common Name")
	algo := fs.String("algo", "ed25519", "Key algorithm")
	starter := fs.Bool("starter", false, "Write a starter mgtls.yaml fleet manifest if absent")
	force := fs.Bool("force", false, "Overwrite starter mgtls.yaml if it already exists")
	nonInteractive := fs.Bool("non-interactive", false, "Non-interactive mode for CI and AI agents")
	yes := fs.Bool("yes", false, "Alias for --non-interactive")
	quiet := fs.Bool("quiet", false, "Suppress Next steps hints on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = nonInteractive
	_ = yes

	s, err := store.New(*storeDir)
	if err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	res := map[string]any{
		"store_dir": s.BaseDir,
		"status":    "initialized",
	}
	if *withRoot {
		if existingCA, getErr := s.GetCA(*rootName); getErr == nil && !*force {
			res["root_ca"] = *existingCA
		} else {
			caRes, err := pki.CreateCA(s, pki.CARequest{
				Name:       *rootName,
				CommonName: *rootCN,
				Algorithm:  *algo,
			})
			if err != nil {
				return err
			}
			res["root_ca"] = caRes.Record
		}
	}
	if *starter {
		manifestFile := "mgtls.yaml"
		if _, statErr := os.Stat(manifestFile); os.IsNotExist(statErr) || *force {
			if err := os.WriteFile(manifestFile, []byte(starterManifestYAML), 0644); err != nil {
				return fmt.Errorf("write starter %s: %w", manifestFile, err)
			}
			res["starter_manifest"] = manifestFile
		}
	}
	if err := writeJSON(stdout, res); err != nil {
		return err
	}
	if !*quiet && stderr != nil {
		fmt.Fprintf(stderr, "Initialized mgtls workspace in %s\nNext steps:\n  1. mgtls doctor                                     # verify store health and key permissions\n  2. mgtls target generate --type fastapi --name demo # scaffold a ready-to-run mTLS bundle\n  3. mgtls guide                                      # view the full workflow guide\n", s.BaseDir)
	}
	return nil
}

func runCA(defaultStoreDir string, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("ca subcommand required: create | list | trust-script")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "create":
		fs := flag.NewFlagSet("ca create", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		name := fs.String("name", "root-ca", "CA name")
		cn := fs.String("cn", "mgtls Root CA", "Common Name")
		org := fs.String("org", "mgtls PKI", "Organization")
		country := fs.String("country", "US", "Country")
		parent := fs.String("parent", "", "Parent CA name (non-empty creates Intermediate CA)")
		algo := fs.String("algo", "ed25519", "Algorithm (ed25519, ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096)")
		days := fs.Int("days", 0, "Validity in days")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		res, err := pki.CreateCA(s, pki.CARequest{
			Name:         *name,
			CommonName:   *cn,
			Organization: *org,
			Country:      *country,
			ParentCA:     *parent,
			Algorithm:    *algo,
			ValidDays:    *days,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	case "list":
		fs := flag.NewFlagSet("ca list", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		m, err := s.LoadManifest()
		if err != nil {
			return err
		}
		return writeJSON(stdout, m.CAs)

	case "trust-script":
		fs := flag.NewFlagSet("ca trust-script", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		name := fs.String("name", "root-ca", "CA name in store")
		certPath := fs.String("cert", "", "Explicit CA cert path")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		path := *certPath
		if path == "" {
			caRec, err := s.GetCA(*name)
			if err != nil {
				return err
			}
			path = caRec.CertPath
		}
		scripts, err := pki.GenerateTrustScript(path, *name)
		if err != nil {
			return err
		}
		return writeJSON(stdout, scripts)

	default:
		return fmt.Errorf("unknown ca subcommand %q", sub)
	}
}

func runCert(defaultStoreDir string, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("cert subcommand required: issue | self-sign | inspect | verify | revoke")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "issue":
		fs := flag.NewFlagSet("cert issue", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		name := fs.String("name", "", "Certificate name")
		caName := fs.String("ca", "root-ca", "Signing CA name")
		cn := fs.String("cn", "localhost", "Common Name")
		role := fs.String("role", "mtls", "Role (server, client, mtls)")
		algo := fs.String("algo", "ed25519", "Key algorithm")
		days := fs.Int("days", 365, "Validity days")
		dns := fs.String("dns", "", "Comma-separated DNS SANs")
		ips := fs.String("ip", "", "Comma-separated IP SANs")
		uris := fs.String("uri", "", "Comma-separated URI SANs")
		emails := fs.String("email", "", "Comma-separated Email SANs")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *name == "" {
			*name = *cn
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		res, err := pki.IssueCert(s, pki.CertRequest{
			Name:        *name,
			CommonName:  *cn,
			CAName:      *caName,
			Role:        *role,
			Algorithm:   *algo,
			ValidDays:   *days,
			DNSNames:    splitCSV(*dns),
			IPAddresses: splitCSV(*ips),
			URIs:        splitCSV(*uris),
			Emails:      splitCSV(*emails),
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	case "self-sign":
		fs := flag.NewFlagSet("cert self-sign", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		name := fs.String("name", "", "Certificate name")
		cn := fs.String("cn", "localhost", "Common Name")
		org := fs.String("org", "mgtls Self-Signed", "Organization")
		role := fs.String("role", "mtls", "Role (server, client, mtls)")
		algo := fs.String("algo", "ed25519", "Key algorithm")
		days := fs.Int("days", 365, "Validity days")
		dns := fs.String("dns", "localhost", "Comma-separated DNS SANs")
		ips := fs.String("ip", "127.0.0.1", "Comma-separated IP SANs")
		uris := fs.String("uri", "", "Comma-separated URI SANs")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *name == "" {
			*name = *cn
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		res, err := pki.IssueSelfSigned(s, pki.SelfSignedRequest{
			Name:         *name,
			CommonName:   *cn,
			Organization: *org,
			Role:         *role,
			Algorithm:    *algo,
			ValidDays:    *days,
			DNSNames:     splitCSV(*dns),
			IPAddresses:  splitCSV(*ips),
			URIs:         splitCSV(*uris),
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	case "inspect":
		fs := flag.NewFlagSet("cert inspect", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		certPath := fs.String("cert", "", "Path to certificate PEM")
		name := fs.String("name", "", "Certificate or CA name in store")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		path := *certPath
		if path == "" && *name != "" {
			s, err := store.New(*storeDir)
			if err != nil {
				return err
			}
			if c, err := s.GetCert(*name); err == nil {
				path = c.CertPath
			} else if ca, err := s.GetCA(*name); err == nil {
				path = ca.CertPath
			}
		}
		if path == "" {
			return fmt.Errorf("--cert or --name is required")
		}
		info, err := pki.InspectCert(path)
		if err != nil {
			return err
		}
		return writeJSON(stdout, info)

	case "verify":
		fs := flag.NewFlagSet("cert verify", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		certPath := fs.String("cert", "", "Certificate PEM path")
		name := fs.String("name", "", "Certificate name in store")
		caBundle := fs.String("ca-bundle", "", "CA bundle PEM path")
		caName := fs.String("ca", "", "CA name in store")
		crlPath := fs.String("crl", "", "Optional CRL PEM path")
		dnsName := fs.String("dns", "", "DNS name to verify")
		role := fs.String("role", "", "Role to verify (server, client, mtls)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		cPath := *certPath
		if cPath == "" && *name != "" {
			rec, err := s.GetCert(*name)
			if err != nil {
				return err
			}
			cPath = rec.FullChainPath
			if *caName == "" && rec.CAName != "" {
				*caName = rec.CAName
			}
		}
		caPath := *caBundle
		if caPath == "" && *caName != "" {
			if caRec, err := s.GetCA(*caName); err == nil {
				caPath = caRec.ChainPath
			} else if _, statErr := os.Stat(*caName); statErr == nil {
				caPath = *caName
			} else {
				return err
			}
		}
		res, err := pki.VerifyChain(cPath, caPath, *crlPath, *dnsName, *role)
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	case "revoke":
		fs := flag.NewFlagSet("cert revoke", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		caName := fs.String("ca", "root-ca", "Issuing CA name")
		certName := fs.String("name", "", "Certificate name to revoke")
		reason := fs.Int("reason", 0, "CRL reason code")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		crlPath, err := pki.RevokeCert(s, *caName, *certName, *reason)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{
			"revoked":  true,
			"ca":       *caName,
			"cert":     *certName,
			"crl_path": crlPath,
		})

	default:
		return fmt.Errorf("unknown cert subcommand %q", sub)
	}
}

func runSSH(defaultStoreDir string, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("ssh subcommand required: ca-create | sign-user | sign-host | inspect | config")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "ca-create":
		fs := flag.NewFlagSet("ssh ca-create", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		name := fs.String("name", "ssh-user-ca", "SSH CA name")
		caType := fs.String("type", "user", "SSH CA type (user or host)")
		algo := fs.String("algo", "ed25519", "Key algorithm (ed25519, ecdsa-p256, rsa-4096)")
		comment := fs.String("comment", "", "SSH key comment")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		res, err := sshca.CreateSSHCA(s, sshca.SSHCARequest{
			Name:      *name,
			CAType:    *caType,
			Algorithm: *algo,
			Comment:   *comment,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	case "sign", "sign-user", "sign-host":
		defaultType := "user"
		if sub == "sign-host" {
			defaultType = "host"
		}
		fs := flag.NewFlagSet("ssh "+sub, flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		certTypeFlag := fs.String("type", defaultType, "Certificate type (user or host)")
		name := fs.String("name", "", "Certificate record name")
		caName := fs.String("ca", "", "Signing SSH CA name")
		keyID := fs.String("key-id", "", "Certificate Key ID")
		principals := fs.String("principals", "", "Comma-separated principals (usernames or hostnames)")
		hours := fs.Int("hours", 0, "Validity in hours")
		algo := fs.String("algo", "ed25519", "Key algorithm if generating new keypair")
		pubKey := fs.String("pub-key", "", "Optional existing .pub file to sign")
		agentSock := fs.String("agent-socket", "", "Optional SSH_AUTH_SOCK path for hardware/ssh-agent CA signing")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		certType := *certTypeFlag
		if *caName == "" {
			*caName = "ssh-" + certType + "-ca"
		}
		if *name == "" {
			*name = *keyID
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		res, err := sshca.SignSSHCert(s, sshca.SignSSHRequest{
			Name:           *name,
			CAName:         *caName,
			CertType:       certType,
			KeyID:          *keyID,
			Principals:     splitCSV(*principals),
			ValidHours:     *hours,
			Algorithm:      *algo,
			ExistingPubKey: *pubKey,
			AgentSocket:    *agentSock,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	case "inspect":
		fs := flag.NewFlagSet("ssh inspect", flag.ContinueOnError)
		certPath := fs.String("cert", "", "Path to *-cert.pub")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		info, err := sshca.InspectSSHCert(*certPath)
		if err != nil {
			return err
		}
		return writeJSON(stdout, info)

	case "config", "config-bundle":
		fs := flag.NewFlagSet("ssh config", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		name := fs.String("name", "openssh-bundle", "Config bundle name")
		userCA := fs.String("user-ca", "", "User CA name")
		hostCA := fs.String("host-ca", "", "Host CA name")
		hostCert := fs.String("host-cert", "", "Host certificate name")
		userCert := fs.String("user-cert", "", "User certificate name")
		patterns := fs.String("host-patterns", "*", "Comma-separated known_hosts patterns")
		hosts := fs.String("hosts", "", "Alias for --host-patterns")
		principals := fs.String("principals", "", "Comma-separated principals; each may log in only as the same-named account")
		var accounts accountFlag
		fs.Var(&accounts, "account", "Repeatable ACCOUNT=PRINCIPAL[,PRINCIPAL...]: principals allowed to log in as ACCOUNT (e.g. --account deploy=alice,ci)")
		outDir := fs.String("out", "", "Output directory")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		patStr := *patterns
		if *hosts != "" {
			patStr = *hosts
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		res, err := sshca.GenerateSSHConfigBundle(s, sshca.SSHConfigRequest{
			Name:              *name,
			UserCAName:        *userCA,
			HostCAName:        *hostCA,
			HostCertName:      *hostCert,
			UserCertName:      *userCert,
			HostPatterns:      splitCSV(patStr),
			Principals:        splitCSV(*principals),
			AccountPrincipals: accounts.m,
			OutputDir:         *outDir,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	default:
		return fmt.Errorf("unknown ssh subcommand %q", sub)
	}
}

func runACME(ctx context.Context, defaultStoreDir string, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("acme subcommand required: providers | obtain | renew-check")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "providers":
		return writeJSON(stdout, acme.ListProviders())

	case "obtain":
		fs := flag.NewFlagSet("acme obtain", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		name := fs.String("name", "", "ACME certificate name")
		provider := fs.String("provider", "letsencrypt", "Provider (letsencrypt, letsencrypt-staging, zerossl, buypass, google, custom)")
		dirURL := fs.String("directory-url", "", "Custom ACME v2 directory URL")
		email := fs.String("email", "", "Contact email")
		domains := fs.String("domains", "", "Comma-separated domains")
		challenge := fs.String("challenge", "http-01", "Challenge type (http-01, tls-alpn-01, dns-01)")
		httpPort := fs.Int("http-port", 0, "Ephemeral HTTP-01 port")
		webroot := fs.String("webroot", "", "Webroot directory for HTTP-01")
		dnsHook := fs.String("dns-hook", "", "Shell hook for DNS-01")
		eabKID := fs.String("eab-kid", "", "External Account Binding Key ID")
		eabHMAC := fs.String("eab-hmac", "", "External Account Binding base64url HMAC key")
		skipVerify := fs.Bool("insecure-skip-verify", false, "Skip TLS verification on ACME directory (testing only)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		domList := splitCSV(*domains)
		if *name == "" && len(domList) > 0 {
			*name = domList[0]
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		res, err := acme.ObtainCertificate(ctx, s, acme.ObtainRequest{
			Name:          *name,
			Provider:      *provider,
			DirectoryURL:  *dirURL,
			Email:         *email,
			Domains:       domList,
			ChallengeType: *challenge,
			HTTPPort:      *httpPort,
			WebrootDir:    *webroot,
			DNSExecHook:   *dnsHook,
			EABKID:        *eabKID,
			EABHMACKey:    *eabHMAC,
			SkipVerifyTLS: *skipVerify,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	case "renew-check":
		fs := flag.NewFlagSet("acme renew-check", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		days := fs.Int("days", 30, "Threshold days before expiry")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		expiring, err := acme.CheckRenewal(s, *days)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{
			"threshold_days": *days,
			"expiring":       expiring,
		})

	default:
		return fmt.Errorf("unknown acme subcommand %q", sub)
	}
}

func runTarget(defaultStoreDir string, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("target subcommand required: list | generate")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		return writeJSON(stdout, targets.SupportedTargets())

	case "generate":
		// Support positional target type (e.g. `mgtls target generate fastapi --name my-api`) or `--type fastapi`
		var positionalType string
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			positionalType = rest[0]
			rest = rest[1:]
		}
		fs := flag.NewFlagSet("target generate", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		targetType := fs.String("type", positionalType, "Target type (fastapi, springboot, mcp, nginx, vite, proxmox, openssh)")
		name := fs.String("name", "", "Target bundle name")
		outDir := fs.String("out", "", "Output directory")
		host := fs.String("host", "localhost", "Service hostname")
		port := fs.Int("port", 0, "Service port")
		mtls := fs.Bool("mtls", true, "Enable mutual TLS (mTLS)")
		caName := fs.String("ca", "root-ca", "CA name in store (auto-created if missing)")
		serverCert := fs.String("server-cert", "", "Server certificate name in store (auto-issued if missing)")
		clientCert := fs.String("client-cert", "", "Client certificate name in store (auto-issued if missing)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *targetType == "" && positionalType != "" {
			*targetType = positionalType
		}
		if *targetType == "" {
			return fmt.Errorf("target type is required (e.g. fastapi, springboot, mcp, nginx, vite, proxmox, openssh)")
		}
		if *name == "" {
			*name = *targetType + "-bundle"
		}

		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		if err := s.Init(); err != nil {
			return err
		}

		req := targets.GenerateRequest{
			Name:       *name,
			TargetType: *targetType,
			OutputDir:  *outDir,
			Host:       *host,
			Port:       *port,
			MutualTLS:  *mtls,
			CAName:     *caName,
			ServerCert: *serverCert,
			ClientCert: *clientCert,
		}

		// Auto-provision or link PKI certs for X.509 targets so `mgtls target generate <type>` works in 1 command!
		if *targetType != "openssh" {
			caRec, err := s.GetCA(*caName)
			if err != nil {
				caRes, createErr := pki.CreateCA(s, pki.CARequest{
					Name:       *caName,
					CommonName: *caName + " Root CA",
				})
				if createErr != nil {
					return createErr
				}
				caRec = &caRes.Record
			}
			req.CACertPath = caRec.ChainPath

			srvName := *serverCert
			if srvName == "" {
				srvName = *name + "-server"
				req.ServerCert = srvName
			}
			srvRec, err := s.GetCert(srvName)
			if err != nil {
				srvRes, issueErr := pki.IssueCert(s, pki.CertRequest{
					Name:        srvName,
					CommonName:  *host,
					CAName:      *caName,
					Role:        "mtls",
					DNSNames:    []string{*host, "localhost"},
					IPAddresses: []string{"127.0.0.1"},
				})
				if issueErr != nil {
					return issueErr
				}
				srvRec = &srvRes.Record
			}
			req.ServerCertPath = srvRec.FullChainPath
			req.ServerKeyPath = srvRec.KeyPath

			if *mtls {
				cliName := *clientCert
				if cliName == "" {
					cliName = *name + "-client"
					req.ClientCert = cliName
				}
				cliRec, err := s.GetCert(cliName)
				if err != nil {
					cliRes, issueErr := pki.IssueCert(s, pki.CertRequest{
						Name:       cliName,
						CommonName: cliName,
						CAName:     *caName,
						Role:       "client",
					})
					if issueErr != nil {
						return issueErr
					}
					cliRec = &cliRes.Record
				}
				req.ClientCertPath = cliRec.CertPath
				req.ClientKeyPath = cliRec.KeyPath
			}
		}

		res, err := targets.Generate(s, req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	default:
		return fmt.Errorf("unknown target subcommand %q", sub)
	}
}

func runApply(ctx context.Context, defaultStoreDir string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	file := fs.String("f", "mgtls.yaml", "Path to declarative YAML/JSON manifest")
	quiet := fs.Bool("quiet", false, "Suppress Next steps hints on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	spec, err := profile.LoadFleetSpec(*file)
	if err != nil {
		return err
	}
	effectiveStoreDir := *storeDir
	if spec.StoreDir != "" && *storeDir == ".mgtls" {
		effectiveStoreDir = spec.StoreDir
	}
	s, err := store.New(effectiveStoreDir)
	if err != nil {
		return err
	}
	report, err := profile.Apply(ctx, s, spec)
	if err != nil {
		return err
	}
	if err := writeJSON(stdout, report); err != nil {
		return err
	}
	if !*quiet && stderr != nil {
		fmt.Fprintf(stderr, "Applied fleet manifest %s\nNext steps:\n  1. mgtls doctor  # audit key permissions and certificate validity\n  2. mgtls status  # inspect the reconciled store inventory\n", *file)
	}
	return nil
}

func runStatus(defaultStoreDir string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	_ = fs.Bool("json", true, "Output JSON (default true)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := store.New(*storeDir)
	if err != nil {
		return err
	}
	m, err := s.LoadManifest()
	if err != nil {
		return err
	}
	return writeJSON(stdout, m)
}

func runDoctor(defaultStoreDir string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	warnDays := fs.Int("warn-days", 30, "Warn threshold in days")
	quiet := fs.Bool("quiet", false, "Suppress Next steps hints on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := store.New(*storeDir)
	if err != nil {
		return err
	}
	rep, err := profile.RunDoctor(s, *warnDays)
	if err != nil {
		return err
	}
	if err := writeJSON(stdout, rep); err != nil {
		return err
	}
	if !*quiet && stderr != nil {
		fmt.Fprintf(stderr, "Next steps:\n  1. mgtls status        # inspect managed CAs, certificates, and targets\n  2. mgtls apply -f ...  # reconcile declarative fleet manifests\n  3. mgtls guide         # view the full workflow guide\n")
	}
	return nil
}

func runMCP(ctx context.Context, defaultStoreDir string, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	transport := fs.String("transport", "stdio", "Transport: stdio or http")
	addr := fs.String("addr", "127.0.0.1:8443", "Listen address for http/https/mtls transport")
	tlsCert := fs.String("tls-cert", "", "Optional server TLS certificate PEM for HTTPS/mTLS MCP server")
	tlsKey := fs.String("tls-key", "", "Optional server TLS private key PEM for HTTPS/mTLS MCP server")
	clientCA := fs.String("client-ca", "", "Client CA bundle PEM to require mTLS on MCP server")
	tokenFile := fs.String("token-file", "", "File holding the bearer token required on HTTP requests (default: $MGTLS_MCP_TOKEN)")
	insecureNoAuth := fs.Bool("insecure-no-auth", false, "Allow an unauthenticated HTTP MCP server (loopback addresses only)")
	allowExec := fs.Bool("allow-exec-hooks", false, "Allow MCP callers to pass acme_obtain dns_exec_hook / skip_verify_tls")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := store.New(*storeDir)
	if err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	srv := mcpserver.NewServer(s)
	srv.AllowExecHooks = *allowExec
	srv.AllowInsecureNoAuth = *insecureNoAuth
	srv.AuthToken = strings.TrimSpace(os.Getenv("MGTLS_MCP_TOKEN"))
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read --token-file: %w", err)
		}
		srv.AuthToken = strings.TrimSpace(string(raw))
	}
	if srv.AuthToken != "" && len(srv.AuthToken) < 32 {
		return errors.New("MCP bearer token must be at least 32 characters (e.g. `openssl rand -hex 32`)")
	}
	switch *transport {
	case "stdio":
		return srv.ServeStdio(ctx, stdin, stdout)
	case "http", "https", "mtls":
		return srv.ServeHTTP(ctx, *addr, *tlsCert, *tlsKey, *clientCA)
	default:
		return fmt.Errorf("unsupported mcp transport %q (expected stdio or http)", *transport)
	}
}

func runWatch(ctx context.Context, defaultStoreDir string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	file := fs.String("f", "", "Optional declarative YAML/JSON manifest (mgtls.yaml)")
	manifestFlag := fs.String("manifest", "", "Alias for -f")
	interval := fs.Duration("interval", 12*time.Hour, "Check interval (e.g. 12h, 1h, 5m)")
	renewBefore := fs.Duration("renew-before", 720*time.Hour, "Renew certificates expiring within this duration (default 720h = 30d)")
	onRenew := fs.String("on-renew", "", "Shell command hook to execute when any certificate is renewed")
	once := fs.Bool("once", false, "Run a single renewal pass and exit")
	reissueRevoked := fs.Bool("reissue-revoked", false, "Rotate revoked certificates (reissue with a new key) instead of honoring the revocation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	manifestPath := *file
	if manifestPath == "" {
		manifestPath = *manifestFlag
	}
	s, err := store.New(*storeDir)
	if err != nil {
		return err
	}
	return profile.Watch(ctx, s, profile.WatchOptions{
		ManifestPath:   manifestPath,
		Interval:       *interval,
		RenewBefore:    *renewBefore,
		OnRenewHook:    *onRenew,
		Once:           *once,
		ReissueRevoked: *reissueRevoked,
	}, func(rep *profile.RenewalCycleReport) {
		if err := writeJSON(stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "watch: write report: %v\n", err)
		}
	})
}

func runSystemd(defaultStoreDir string, args []string, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "generate" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("systemd generate", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	unitName := fs.String("unit-name", "mgtls-renew", "systemd unit base name")
	binPath := fs.String("binary-path", "/usr/local/bin/mgtls", "Path to mgtls binary")
	manifestPath := fs.String("manifest", "", "Optional path to mgtls.yaml")
	calendar := fs.String("calendar", "*-*-* 00,12:00:00", "systemd OnCalendar schedule")
	renewBefore := fs.String("renew-before", "720h", "Renew window duration (e.g. 720h)")
	onRenew := fs.String("on-renew", "", "Optional reload command hook on renewal")
	outDir := fs.String("out", "", "Output directory for .service and .timer files")
	reissueRevoked := fs.Bool("reissue-revoked", false, "Add --reissue-revoked to the unit (rotate revoked certificates)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := store.New(*storeDir)
	if err != nil {
		return err
	}
	bundle, err := profile.GenerateSystemdUnits(s, profile.SystemdRequest{
		UnitName:       *unitName,
		BinaryPath:     *binPath,
		ManifestPath:   *manifestPath,
		StoreDir:       s.BaseDir,
		Calendar:       *calendar,
		RenewBefore:    *renewBefore,
		OnRenewHook:    *onRenew,
		OutputDir:      *outDir,
		ReissueRevoked: *reissueRevoked,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, bundle)
}

func runProbe(defaultStoreDir string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
	addr := fs.String("addr", "", "Target host:port to probe (e.g. localhost:8443)")
	sni := fs.String("sni", "", "Optional SNI hostname override")
	caName := fs.String("ca", "", "Optional .mgtls CA name to verify peer chain against")
	caCert := fs.String("ca-cert", "", "Optional CA certificate PEM path")
	clientCertName := fs.String("client-cert-name", "", "Optional .mgtls leaf certificate name for mTLS")
	clientCert := fs.String("client-cert", "", "Optional client certificate PEM path for mTLS")
	clientKey := fs.String("client-key", "", "Optional client private key PEM path for mTLS")
	alpn := fs.String("alpn", "", "Optional comma-separated ALPN protocols (e.g. h2,http/1.1)")
	timeout := fs.Duration("timeout", 5*time.Second, "Connection & handshake timeout")
	strict := fs.Bool("strict", false, "Return non-zero exit error if peer chain is unverified or has warnings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targetAddr := *addr
	if targetAddr == "" && fs.NArg() > 0 {
		targetAddr = fs.Arg(0)
	}
	s, err := store.New(*storeDir)
	if err != nil {
		return err
	}
	rep, err := pki.ProbeEndpoint(s, pki.ProbeRequest{
		Address:        targetAddr,
		ServerName:     *sni,
		CAName:         *caName,
		CACertPath:     *caCert,
		ClientCertName: *clientCertName,
		ClientCertPath: *clientCert,
		ClientKeyPath:  *clientKey,
		ALPN:           splitCSV(*alpn),
		Timeout:        *timeout,
	})
	if err != nil {
		return err
	}
	if err := writeJSON(stdout, rep); err != nil {
		return err
	}
	if *strict {
		if !rep.Verified {
			return fmt.Errorf("probe strict check failed: %s", rep.VerificationError)
		}
		if len(rep.Warnings) > 0 {
			return fmt.Errorf("probe strict check failed with %d warning(s): %s", len(rep.Warnings), strings.Join(rep.Warnings, "; "))
		}
	}
	return nil
}

func runOCSP(ctx context.Context, defaultStoreDir string, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("ocsp subcommand required: serve or verify")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "serve":
		fs := flag.NewFlagSet("ocsp serve", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		caName := fs.String("ca", "root-ca", "CA name in .mgtls store to sign OCSP responses")
		addr := fs.String("addr", "127.0.0.1:8888", "Listen address for HTTP OCSP responder")
		nextUpdate := fs.Duration("next-update", 24*time.Hour, "OCSP NextUpdate validity window")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		return pki.ServeOCSP(ctx, s, pki.OCSPResponderOptions{
			CAName:             *caName,
			ListenAddr:         *addr,
			NextUpdateDuration: *nextUpdate,
		})

	case "verify":
		fs := flag.NewFlagSet("ocsp verify", flag.ContinueOnError)
		storeDir := fs.String("store-dir", defaultStoreDir, "Store directory")
		certName := fs.String("name", "", "Certificate name in .mgtls store")
		certPath := fs.String("cert", "", "Certificate PEM path")
		caName := fs.String("ca", "", "Issuing CA name in .mgtls store")
		caCert := fs.String("ca-cert", "", "Issuing CA certificate PEM path")
		responderURL := fs.String("url", "", "Optional HTTP OCSP responder URL")
		stapledAddr := fs.String("stapled", "", "Optional live TLS host:port to verify OCSP stapling")
		timeout := fs.Duration("timeout", 5*time.Second, "Timeout for OCSP query or TLS dial")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		s, err := store.New(*storeDir)
		if err != nil {
			return err
		}
		rep, err := pki.VerifyOCSP(s, pki.VerifyOCSPRequest{
			CertName:       *certName,
			CertPath:       *certPath,
			CAName:         *caName,
			CACertPath:     *caCert,
			ResponderURL:   *responderURL,
			StapledAddress: *stapledAddr,
			Timeout:        *timeout,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, rep)

	default:
		return fmt.Errorf("unknown ocsp subcommand %q (expected serve or verify)", sub)
	}
}
