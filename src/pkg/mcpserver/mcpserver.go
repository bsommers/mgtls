package mcpserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sysadmin/mgtls/src/pkg/acme"
	"github.com/sysadmin/mgtls/src/pkg/pki"
	"github.com/sysadmin/mgtls/src/pkg/profile"
	"github.com/sysadmin/mgtls/src/pkg/sshca"
	"github.com/sysadmin/mgtls/src/pkg/store"
	"github.com/sysadmin/mgtls/src/pkg/targets"
)

// Server implements a Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio and HTTP/HTTPS/mTLS.
type Server struct {
	Store *store.Store
}

// NewServer creates a new MCP Server bound to the given cryptographic store.
func NewServer(s *store.Store) *Server {
	return &Server{Store: s}
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type mcpCallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpCallToolResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError"`
}

type mcpResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

type mcpResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type mcpPromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type mcpPrompt struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Arguments   []mcpPromptArgument `json:"arguments,omitempty"`
}

type mcpPromptMessage struct {
	Role    string     `json:"role"`
	Content mcpContent `json:"content"`
}

// HandleJSONRPC processes a single JSON-RPC 2.0 request or notification and returns the response payload (or nil for notifications).
func (srv *Server) HandleJSONRPC(ctx context.Context, raw []byte) ([]byte, error) {
	var req jsonRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return marshalError(json.RawMessage("null"), -32700, "Parse error: "+err.Error())
	}
	if req.JSONRPC != "2.0" && req.Method == "" {
		return marshalError(normalizeID(req.ID), -32600, "Invalid Request")
	}

	// JSON-RPC notifications (no ID or notifications/* method) do not return a response body.
	if strings.HasPrefix(req.Method, "notifications/") || len(req.ID) == 0 {
		return nil, nil
	}

	id := normalizeID(req.ID)

	switch req.Method {
	case "initialize":
		res := map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"subscribe": false, "listChanged": false},
				"prompts":   map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    "mgtls",
				"version": "1.4.0",
			},
		}
		return marshalResult(id, res)

	case "ping":
		return marshalResult(id, map[string]any{})

	case "tools/list":
		return marshalResult(id, map[string]any{
			"tools": srv.listTools(),
		})

	case "tools/call":
		var params mcpCallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return marshalError(id, -32602, "Invalid params: "+err.Error())
		}
		toolRes := srv.callTool(ctx, params)
		return marshalResult(id, toolRes)

	case "resources/list":
		return marshalResult(id, map[string]any{
			"resources": srv.listResources(),
		})

	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.URI == "" {
			return marshalError(id, -32602, "Invalid params: uri is required")
		}
		contents, err := srv.readResource(params.URI)
		if err != nil {
			return marshalError(id, -32602, err.Error())
		}
		return marshalResult(id, map[string]any{
			"contents": contents,
		})

	case "prompts/list":
		return marshalResult(id, map[string]any{
			"prompts": srv.listPrompts(),
		})

	case "prompts/get":
		var params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
			return marshalError(id, -32602, "Invalid params: prompt name is required")
		}
		desc, msgs, err := srv.getPrompt(params.Name, params.Arguments)
		if err != nil {
			return marshalError(id, -32602, err.Error())
		}
		return marshalResult(id, map[string]any{
			"description": desc,
			"messages":    msgs,
		})

	default:
		return marshalError(id, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func normalizeID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func marshalResult(id json.RawMessage, result any) ([]byte, error) {
	return json.Marshal(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func marshalError(id json.RawMessage, code int, msg string) ([]byte, error) {
	return json.Marshal(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: msg,
		},
	})
}

func (srv *Server) listTools() []mcpTool {
	return []mcpTool{
		{
			Name:        "pki_create_ca",
			Description: "Create an X.509 Root CA or Intermediate CA (signed by parent_ca) in the mgtls store",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":         map[string]any{"type": "string", "description": "Unique CA identifier in store"},
					"common_name":  map[string]any{"type": "string", "description": "Subject CommonName"},
					"organization": map[string]any{"type": "string", "description": "Subject Organization"},
					"country":      map[string]any{"type": "string", "description": "Subject Country (2-letter code)"},
					"parent_ca":    map[string]any{"type": "string", "description": "Optional parent CA name to sign an Intermediate CA"},
					"algorithm":    map[string]any{"type": "string", "description": "ed25519 (default), ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096"},
					"valid_days":   map[string]any{"type": "integer", "description": "Validity period in days"},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "pki_issue_cert",
			Description: "Issue an X.509 Server, Client, or dual mTLS certificate signed by a CA in the store",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":         map[string]any{"type": "string", "description": "Unique certificate name in store"},
					"common_name":  map[string]any{"type": "string", "description": "Subject CommonName"},
					"ca_name":      map[string]any{"type": "string", "description": "Signing CA name in store"},
					"role":         map[string]any{"type": "string", "description": "server, client, or mtls (default: mtls)"},
					"algorithm":    map[string]any{"type": "string", "description": "ed25519 (default), ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096"},
					"valid_days":   map[string]any{"type": "integer", "description": "Validity in days (default: 365)"},
					"dns_names":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "DNS Subject Alternative Names"},
					"ip_addresses": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "IP Subject Alternative Names"},
					"uris":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "URI / SPIFFE SANs"},
				},
				"required": []string{"name", "ca_name"},
			},
		},
		{
			Name:        "pki_self_sign",
			Description: "Issue a standalone self-signed X.509 certificate (Server, Client, or mTLS)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":         map[string]any{"type": "string"},
					"common_name":  map[string]any{"type": "string"},
					"organization": map[string]any{"type": "string"},
					"role":         map[string]any{"type": "string", "description": "server, client, or mtls"},
					"algorithm":    map[string]any{"type": "string"},
					"valid_days":   map[string]any{"type": "integer"},
					"dns_names":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"ip_addresses": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"uris":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "pki_inspect",
			Description: "Inspect an X.509 certificate file or named certificate in store",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cert_path": map[string]any{"type": "string", "description": "Path to PEM/DER certificate file"},
					"cert_name": map[string]any{"type": "string", "description": "Alternative: name of certificate in store"},
				},
			},
		},
		{
			Name:        "pki_verify",
			Description: "Verify an X.509 certificate chain, Extended Key Usage role, SAN DNS/IP, and optional CRL revocation",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cert_path":      map[string]any{"type": "string", "description": "Path to leaf or fullchain PEM"},
					"cert_name":      map[string]any{"type": "string", "description": "Alternative: certificate name in store"},
					"ca_bundle_path": map[string]any{"type": "string", "description": "Path to root CA PEM bundle"},
					"ca_name":        map[string]any{"type": "string", "description": "Alternative: CA name in store"},
					"crl_path":       map[string]any{"type": "string", "description": "Optional path to X.509 CRL file"},
					"dns_name":       map[string]any{"type": "string", "description": "Optional DNS or IP to verify against SAN"},
					"role":           map[string]any{"type": "string", "description": "server, client, or mtls"},
				},
			},
		},
		{
			Name:        "pki_revoke",
			Description: "Revoke an issued certificate in the store and regenerate the CA's signed X.509 CRL",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ca_name":     map[string]any{"type": "string"},
					"cert_name":   map[string]any{"type": "string"},
					"reason_code": map[string]any{"type": "integer", "description": "RFC 5280 CRL reason code (default 0)"},
				},
				"required": []string{"ca_name", "cert_name"},
			},
		},
		{
			Name:        "pki_trust_script",
			Description: "Generate OS trust store installation commands (Debian/Ubuntu, RHEL/Fedora, Arch, macOS, Windows)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ca_name":      map[string]any{"type": "string", "description": "CA name in store"},
					"ca_cert_path": map[string]any{"type": "string", "description": "Direct path to CA certificate"},
					"name":         map[string]any{"type": "string", "description": "Friendly trust anchor name"},
				},
			},
		},
		{
			Name:        "ssh_create_ca",
			Description: "Create an OpenSSH User or Host Certificate Authority keypair",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":      map[string]any{"type": "string"},
					"ca_type":   map[string]any{"type": "string", "description": "user or host"},
					"algorithm": map[string]any{"type": "string", "description": "ed25519 (default), ecdsa-p256, rsa-4096"},
					"comment":   map[string]any{"type": "string"},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "ssh_sign_cert",
			Description: "Sign an OpenSSH User or Host certificate (-cert.pub) with principals and validity window",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":             map[string]any{"type": "string"},
					"ca_name":          map[string]any{"type": "string"},
					"cert_type":        map[string]any{"type": "string", "description": "user or host"},
					"key_id":           map[string]any{"type": "string"},
					"principals":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"valid_hours":      map[string]any{"type": "integer"},
					"algorithm":        map[string]any{"type": "string"},
					"existing_pub_key": map[string]any{"type": "string"},
					"agent_socket":     map[string]any{"type": "string", "description": "Optional SSH_AUTH_SOCK path for hardware/ssh-agent CA signing"},
				},
				"required": []string{"name", "ca_name"},
			},
		},
		{
			Name:        "ssh_inspect",
			Description: "Inspect an OpenSSH certificate file (-cert.pub)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cert_path": map[string]any{"type": "string"},
				},
				"required": []string{"cert_path"},
			},
		},
		{
			Name:        "ssh_config_bundle",
			Description: "Generate OpenSSH sshd_config drop-in, ssh_config drop-in, @cert-authority known_hosts, and authorized_principals",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":           map[string]any{"type": "string"},
					"user_ca_name":   map[string]any{"type": "string"},
					"host_ca_name":   map[string]any{"type": "string"},
					"host_cert_name": map[string]any{"type": "string"},
					"user_cert_name": map[string]any{"type": "string"},
					"host_patterns":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"principals":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"output_dir":     map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "acme_providers",
			Description: "List supported free public ACME v2 Certificate Authorities (Let's Encrypt, ZeroSSL, Buypass, Google)",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "acme_obtain",
			Description: "Obtain a signed TLS certificate from an ACME v2 CA using HTTP-01, TLS-ALPN-01, or DNS-01",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":            map[string]any{"type": "string"},
					"provider":        map[string]any{"type": "string", "description": "letsencrypt, letsencrypt-staging, zerossl, buypass, google, custom"},
					"directory_url":   map[string]any{"type": "string"},
					"email":           map[string]any{"type": "string"},
					"domains":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"challenge_type":  map[string]any{"type": "string", "description": "http-01, tls-alpn-01, dns-01"},
					"http_port":       map[string]any{"type": "integer"},
					"webroot_dir":     map[string]any{"type": "string"},
					"dns_exec_hook":   map[string]any{"type": "string"},
					"eab_kid":         map[string]any{"type": "string"},
					"eab_hmac_key":    map[string]any{"type": "string"},
					"skip_verify_tls": map[string]any{"type": "boolean"},
				},
				"required": []string{"name", "domains"},
			},
		},
		{
			Name:        "target_list",
			Description: "List supported target framework integrations (fastapi, springboot, mcp, nginx, vite, proxmox, openssh, caddy, traefik, envoy, postgres, redis, grpc-go, nodejs-express)",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "target_generate",
			Description: "Generate ready-to-run TLS/mTLS or SSH CA integration configurations for 14 targets (FastAPI, Spring Boot, MCP, NGINX, Vite, Proxmox, OpenSSH, Caddy, Traefik, Envoy, PostgreSQL, Redis, gRPC-Go, Node.js/Express)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":             map[string]any{"type": "string"},
					"target_type":      map[string]any{"type": "string", "description": "fastapi, springboot, mcp, nginx, vite, proxmox, openssh, caddy, traefik, envoy, postgres, redis, grpc-go, nodejs-express"},
					"output_dir":       map[string]any{"type": "string"},
					"host":             map[string]any{"type": "string"},
					"port":             map[string]any{"type": "integer"},
					"mutual_tls":       map[string]any{"type": "boolean"},
					"ca_name":          map[string]any{"type": "string"},
					"ca_cert_path":     map[string]any{"type": "string"},
					"server_cert":      map[string]any{"type": "string"},
					"server_cert_path": map[string]any{"type": "string"},
					"server_key_path":  map[string]any{"type": "string"},
					"client_cert":      map[string]any{"type": "string"},
					"client_cert_path": map[string]any{"type": "string"},
					"client_key_path":  map[string]any{"type": "string"},
					"extra":            map[string]any{"type": "object"},
				},
				"required": []string{"target_type"},
			},
		},
		{
			Name:        "profile_apply",
			Description: "Apply a declarative YAML or JSON fleet manifest (mgtls.yaml) from a file path or inline manifest string",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"manifest_path":    map[string]any{"type": "string", "description": "Path to mgtls.yaml or JSON manifest"},
					"manifest_content": map[string]any{"type": "string", "description": "Inline YAML or JSON manifest content"},
				},
			},
		},
		{
			Name:        "store_status",
			Description: "Return the full cryptographic store manifest inventory of CAs, certificates, SSH CAs, ACME orders, and generated target bundles",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "store_doctor",
			Description: "Audit the cryptographic store for expiring/expired certificates, revocations, missing files, and private key permission violations",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"warn_days": map[string]any{"type": "integer", "description": "Days before expiration to warn (default 30)"},
				},
			},
		},
		{
			Name:        "pki_probe",
			Description: "Probe a live TLS or Mutual TLS endpoint (host:port) to inspect negotiated TLS version, cipher suite, ALPN, peer certificate chain, SANs, expiration, and CA trust verification",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"address":          map[string]any{"type": "string", "description": "Target host:port to probe (e.g. localhost:8443)"},
					"server_name":      map[string]any{"type": "string", "description": "Optional SNI hostname override"},
					"ca_name":          map[string]any{"type": "string", "description": "Optional .mgtls CA name to verify peer chain against"},
					"ca_cert_path":     map[string]any{"type": "string", "description": "Optional CA certificate PEM path"},
					"client_cert_name": map[string]any{"type": "string", "description": "Optional .mgtls leaf certificate name for mTLS"},
					"client_cert_path": map[string]any{"type": "string", "description": "Optional client certificate PEM path"},
					"client_key_path":  map[string]any{"type": "string", "description": "Optional client private key PEM path"},
					"alpn":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required": []string{"address"},
			},
		},
		{
			Name:        "pki_ocsp_verify",
			Description: "Verify RFC 6960 OCSP revocation status for a certificate via local .mgtls CA signing, a live HTTP OCSP responder URL, or a live TLS endpoint's stapled OCSP response",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cert_name":       map[string]any{"type": "string", "description": "Certificate name in .mgtls store"},
					"cert_path":       map[string]any{"type": "string", "description": "Certificate PEM path"},
					"ca_name":         map[string]any{"type": "string", "description": "Issuing CA name in .mgtls store"},
					"ca_cert_path":    map[string]any{"type": "string", "description": "Issuing CA certificate PEM path"},
					"responder_url":   map[string]any{"type": "string", "description": "Optional HTTP OCSP responder URL"},
					"stapled_address": map[string]any{"type": "string", "description": "Optional live TLS host:port to inspect OCSP stapling"},
				},
			},
		},
		{
			Name:        "pki_csr_sign",
			Description: "Sign an externally generated PKCS#10 CSR with a managed CA. The requester keeps the leaf private key; only CN/SANs are taken from the CSR (requested CA/EKU extensions are ignored). Returns the signed certificate and chain.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ca_name":    map[string]any{"type": "string", "description": "Issuing CA name"},
					"csr_pem":    map[string]any{"type": "string", "description": "Inline PEM PKCS#10 certificate request"},
					"csr_path":   map[string]any{"type": "string", "description": "Or path to a .csr.pem file"},
					"name":       map[string]any{"type": "string", "description": "Store name for the issued certificate (default: CSR common name)"},
					"role":       map[string]any{"type": "string", "description": "server, client or mtls (default mtls)"},
					"valid_days": map[string]any{"type": "integer", "description": "Validity in days (default 365)"},
				},
				"required": []string{"ca_name"},
			},
		},
		{
			Name:        "pki_scan",
			Description: "Concurrently scan many TLS endpoints (version, cipher, chain trust, expiry inventory) or, with operation=bundle, compile a multi-CA trust bundle (pem, p7b, p12 truststore)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"operation":        map[string]any{"type": "string", "description": "scan (default) or bundle"},
					"targets":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "host:port targets (scan)"},
					"ca_name":          map[string]any{"type": "string", "description": "CA to verify against (scan)"},
					"ca_cert_path":     map[string]any{"type": "string"},
					"client_cert_name": map[string]any{"type": "string"},
					"concurrency":      map[string]any{"type": "integer", "description": "Parallel probes (default 16, max 256)"},
					"warn_days":        map[string]any{"type": "integer", "description": "Expiry warning threshold (default 30)"},
					"ca_names":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Store CAs to merge (bundle)"},
					"inputs":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "PEM/.p7b files to merge (bundle)"},
					"format":           map[string]any{"type": "string", "description": "pem, p7b, or p12 (bundle)"},
					"password":         map[string]any{"type": "string", "description": "p12 password (bundle)"},
					"out_path":         map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "pki_audit_verify",
			Description: "Verify the tamper-evident SHA-256 hash-chained audit ledger (or list entries); optionally pin the head hash to detect tail truncation",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"expect_head": map[string]any{"type": "string", "description": "Pinned head hash"},
					"list":        map[string]any{"type": "boolean", "description": "List entries instead of verifying"},
					"event":       map[string]any{"type": "string", "description": "Filter by event when listing"},
					"last":        map[string]any{"type": "integer", "description": "Only last N entries when listing"},
				},
			},
		},
		{
			Name:        "pki_svid_issue",
			Description: "SPIFFE X.509-SVID operations: issue (spiffe:// URI SAN leaf), verify (chain, SPIFFE ID, revocation), or bundle (export CA trust bundle as SPIFFE JSON or PEM)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"operation":    map[string]any{"type": "string", "description": "issue (default), verify, or bundle"},
					"name":         map[string]any{"type": "string", "description": "SVID certificate name (issue)"},
					"spiffe_id":    map[string]any{"type": "string", "description": "spiffe://<trust-domain>/<workload> (issue)"},
					"ca_name":      map[string]any{"type": "string", "description": "CA name (default root-ca for issue)"},
					"algorithm":    map[string]any{"type": "string", "description": "Key algorithm (issue)"},
					"valid_days":   map[string]any{"type": "integer", "description": "Validity days (issue, default 1)"},
					"dns_names":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"cert_name":    map[string]any{"type": "string", "description": "Store certificate name (verify)"},
					"cert_path":    map[string]any{"type": "string", "description": "SVID PEM path (verify)"},
					"bundle_path":  map[string]any{"type": "string", "description": "Trust bundle PEM path (verify)"},
					"trust_domain": map[string]any{"type": "string", "description": "Expected trust domain (verify)"},
					"expected_id":  map[string]any{"type": "string", "description": "Expected SPIFFE ID (verify)"},
					"format":       map[string]any{"type": "string", "description": "spiffe (default) or pem (bundle)"},
				},
			},
		},
		{
			Name:        "pki_est_enroll",
			Description: "Enroll or re-enroll an X.509 certificate (or fetch CA certs) against an RFC 7030 Enrollment over Secure Transport (EST) server (/.well-known/est/simpleenroll, /simplereenroll, /cacerts)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_url":           map[string]any{"type": "string", "description": "Base URL of the RFC 7030 EST server (e.g. https://127.0.0.1:8445)"},
					"operation":            map[string]any{"type": "string", "description": "enroll (default), reenroll, or cacerts"},
					"ca_label":             map[string]any{"type": "string", "description": "Optional CA label in /.well-known/est/<label>/..."},
					"name":                 map[string]any{"type": "string", "description": "Certificate/key base name"},
					"common_name":          map[string]any{"type": "string", "description": "Subject Common Name"},
					"algorithm":            map[string]any{"type": "string", "description": "Key algorithm (ed25519, ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096)"},
					"dns_names":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"ip_addresses":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"uris":                 map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"role":                 map[string]any{"type": "string", "description": "server, client, or mtls"},
					"csr_pem":              map[string]any{"type": "string", "description": "Optional inline PKCS#10 CSR PEM"},
					"csr_path":             map[string]any{"type": "string", "description": "Optional PKCS#10 CSR file path"},
					"out_dir":              map[string]any{"type": "string", "description": "Output directory for generated key and enrolled cert"},
					"token":                map[string]any{"type": "string", "description": "Bootstrap enrollment token (Bearer)"},
					"ca_name":              map[string]any{"type": "string", "description": "Optional .mgtls CA name for TLS verification"},
					"ca_cert_path":         map[string]any{"type": "string", "description": "Optional CA PEM path for TLS verification"},
					"client_cert_name":     map[string]any{"type": "string", "description": "Optional .mgtls client cert name for mTLS auth"},
					"client_cert_path":     map[string]any{"type": "string", "description": "Optional client cert PEM path for mTLS auth"},
					"client_key_path":      map[string]any{"type": "string", "description": "Optional client key PEM path for mTLS auth"},
					"insecure_skip_verify": map[string]any{"type": "boolean", "description": "Skip TLS verification when bootstrapping"},
				},
				"required": []string{"server_url"},
			},
		},
	}
}

func (srv *Server) callTool(ctx context.Context, params mcpCallToolParams) mcpCallToolResult {
	res, err := srv.dispatchTool(ctx, params.Name, params.Arguments)
	if err != nil {
		errPayload, _ := json.MarshalIndent(map[string]any{
			"error": err.Error(),
		}, "", "  ")
		return mcpCallToolResult{
			Content: []mcpContent{{Type: "text", Text: string(errPayload)}},
			IsError: true,
		}
	}
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return mcpCallToolResult{
			Content: []mcpContent{{Type: "text", Text: fmt.Sprintf(`{"error": %q}`, err.Error())}},
			IsError: true,
		}
	}
	return mcpCallToolResult{
		Content: []mcpContent{{Type: "text", Text: string(raw)}},
		IsError: false,
	}
}

func decodeArgs[T any](raw json.RawMessage, dst *T) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func (srv *Server) dispatchTool(ctx context.Context, name string, rawArgs json.RawMessage) (any, error) {
	switch name {
	case "pki_create_ca":
		var req pki.CARequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.CreateCA(srv.Store, req)

	case "pki_issue_cert":
		var req pki.CertRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.IssueCert(srv.Store, req)

	case "pki_self_sign":
		var req pki.SelfSignedRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.IssueSelfSigned(srv.Store, req)

	case "pki_inspect":
		var args struct {
			CertPath string `json:"cert_path"`
			CertName string `json:"cert_name"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		certPath := args.CertPath
		if certPath == "" && args.CertName != "" {
			if rec, err := srv.Store.GetCert(args.CertName); err == nil {
				certPath = rec.CertPath
			} else if caRec, err := srv.Store.GetCA(args.CertName); err == nil {
				certPath = caRec.CertPath
			} else {
				return nil, fmt.Errorf("cert_name %q not found in store", args.CertName)
			}
		}
		if certPath == "" {
			return nil, errors.New("cert_path or cert_name is required")
		}
		return pki.InspectCert(certPath)

	case "pki_verify":
		var args struct {
			CertPath     string `json:"cert_path"`
			CertName     string `json:"cert_name"`
			CABundlePath string `json:"ca_bundle_path"`
			CAName       string `json:"ca_name"`
			CRLPath      string `json:"crl_path"`
			DNSName      string `json:"dns_name"`
			Role         string `json:"role"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		certPath := args.CertPath
		if certPath == "" && args.CertName != "" {
			rec, err := srv.Store.GetCert(args.CertName)
			if err != nil {
				return nil, err
			}
			certPath = rec.FullChainPath
			if args.CAName == "" && rec.CAName != "" {
				args.CAName = rec.CAName
			}
		}
		caBundlePath := args.CABundlePath
		if caBundlePath == "" && args.CAName != "" {
			caRec, err := srv.Store.GetCA(args.CAName)
			if err != nil {
				return nil, err
			}
			caBundlePath = caRec.ChainPath
		}
		return pki.VerifyChain(certPath, caBundlePath, args.CRLPath, args.DNSName, args.Role)

	case "pki_revoke":
		var args struct {
			CAName     string `json:"ca_name"`
			CertName   string `json:"cert_name"`
			ReasonCode int    `json:"reason_code"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		crlPath, err := pki.RevokeCert(srv.Store, args.CAName, args.CertName, args.ReasonCode)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"revoked":   true,
			"ca_name":   args.CAName,
			"cert_name": args.CertName,
			"crl_path":  crlPath,
		}, nil

	case "pki_trust_script":
		var args struct {
			CAName     string `json:"ca_name"`
			CACertPath string `json:"ca_cert_path"`
			Name       string `json:"name"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		caPath := args.CACertPath
		name := args.Name
		if caPath == "" && args.CAName != "" {
			caRec, err := srv.Store.GetCA(args.CAName)
			if err != nil {
				return nil, err
			}
			caPath = caRec.CertPath
			if name == "" {
				name = args.CAName
			}
		}
		return pki.GenerateTrustScript(caPath, name)

	case "ssh_create_ca":
		var req sshca.SSHCARequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return sshca.CreateSSHCA(srv.Store, req)

	case "ssh_sign_cert":
		var req sshca.SignSSHRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return sshca.SignSSHCert(srv.Store, req)

	case "ssh_inspect":
		var args struct {
			CertPath string `json:"cert_path"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		return sshca.InspectSSHCert(args.CertPath)

	case "ssh_config_bundle":
		var req sshca.SSHConfigRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return sshca.GenerateSSHConfigBundle(srv.Store, req)

	case "acme_providers":
		return map[string]any{
			"providers": acme.ListProviders(),
		}, nil

	case "acme_obtain":
		var req acme.ObtainRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return acme.ObtainCertificate(ctx, srv.Store, req)

	case "target_list":
		return map[string]any{
			"targets": targets.SupportedTargets(),
		}, nil

	case "target_generate":
		var req targets.GenerateRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		if req.CACertPath == "" && req.CAName != "" {
			if caRec, err := srv.Store.GetCA(req.CAName); err == nil {
				req.CACertPath = caRec.ChainPath
			}
		}
		if req.ServerCert != "" && (req.ServerCertPath == "" || req.ServerKeyPath == "") {
			if certRec, err := srv.Store.GetCert(req.ServerCert); err == nil {
				if req.ServerCertPath == "" {
					req.ServerCertPath = certRec.FullChainPath
				}
				if req.ServerKeyPath == "" {
					req.ServerKeyPath = certRec.KeyPath
				}
				if req.CACertPath == "" && certRec.CAChainPath != "" {
					req.CACertPath = certRec.CAChainPath
				}
			}
		}
		if req.ClientCert != "" && (req.ClientCertPath == "" || req.ClientKeyPath == "") {
			if certRec, err := srv.Store.GetCert(req.ClientCert); err == nil {
				if req.ClientCertPath == "" {
					req.ClientCertPath = certRec.CertPath
				}
				if req.ClientKeyPath == "" {
					req.ClientKeyPath = certRec.KeyPath
				}
			}
		}
		return targets.Generate(srv.Store, req)

	case "profile_apply":
		var args struct {
			ManifestPath    string `json:"manifest_path"`
			ManifestContent string `json:"manifest_content"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		var spec *profile.FleetSpec
		var err error
		if args.ManifestContent != "" {
			spec, err = profile.ParseFleetSpec([]byte(args.ManifestContent))
		} else if args.ManifestPath != "" {
			spec, err = profile.LoadFleetSpec(args.ManifestPath)
		} else {
			return nil, errors.New("manifest_path or manifest_content is required")
		}
		if err != nil {
			return nil, err
		}
		return profile.Apply(ctx, srv.Store, spec)

	case "store_status":
		return srv.Store.LoadManifest()

	case "store_doctor":
		var args struct {
			WarnDays int `json:"warn_days"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		return profile.RunDoctor(srv.Store, args.WarnDays)

	case "pki_probe":
		var req pki.ProbeRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.ProbeEndpoint(srv.Store, req)

	case "pki_ocsp_verify":
		var req pki.VerifyOCSPRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.VerifyOCSP(srv.Store, req)

	case "pki_csr_sign":
		var req pki.SignCSRRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.SignCSR(srv.Store, req)

	case "pki_scan":
		var args struct {
			Operation string `json:"operation,omitempty"` // scan (default) | bundle
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		if strings.EqualFold(strings.TrimSpace(args.Operation), "bundle") {
			var req pki.BundleCompileRequest
			if err := decodeArgs(rawArgs, &req); err != nil {
				return nil, err
			}
			return pki.CompileTrustBundle(srv.Store, req)
		}
		var req pki.ScanRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.ScanTargets(srv.Store, req)

	case "pki_audit_verify":
		var args struct {
			ExpectHead string `json:"expect_head,omitempty"`
			List       bool   `json:"list,omitempty"`
			Event      string `json:"event,omitempty"`
			Last       int    `json:"last,omitempty"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		if args.List {
			return srv.Store.ListAudit(args.Event, args.Last)
		}
		return srv.Store.VerifyAudit(args.ExpectHead)

	case "pki_svid_issue":
		var args struct {
			Operation string `json:"operation,omitempty"` // issue (default), verify, bundle
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		return srv.svidOp(args.Operation, rawArgs)

	case "pki_est_enroll":
		var args struct {
			pki.ESTEnrollRequest
			Operation string `json:"operation,omitempty"`
			OutPath   string `json:"out_path,omitempty"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, err
		}
		switch strings.ToLower(strings.TrimSpace(args.Operation)) {
		case "cacerts":
			return pki.ESTFetchCACerts(srv.Store, pki.ESTCACertsRequest{
				ServerURL:    args.ServerURL,
				CALabel:      args.CALabel,
				CAName:       args.CAName,
				CACertPath:   args.CACertPath,
				InsecureSkip: args.InsecureSkip,
				OutPath:      args.OutPath,
			})
		case "reenroll":
			args.Reenroll = true
			return pki.ESTEnroll(srv.Store, args.ESTEnrollRequest)
		default:
			return pki.ESTEnroll(srv.Store, args.ESTEnrollRequest)
		}

	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

// svidOp dispatches pki_svid_issue operations (issue, verify, bundle).
func (srv *Server) svidOp(op string, rawArgs json.RawMessage) (any, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "verify":
		var req pki.VerifySVIDRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.VerifySVID(srv.Store, req)
	case "bundle":
		var req pki.TrustBundleRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.ExportTrustBundle(srv.Store, req)
	case "", "issue":
		var req pki.SVIDRequest
		if err := decodeArgs(rawArgs, &req); err != nil {
			return nil, err
		}
		return pki.IssueSVID(srv.Store, req)
	default:
		return nil, fmt.Errorf("unknown operation %q (expected issue, verify, or bundle)", op)
	}
}

func (srv *Server) listResources() []mcpResource {
	return []mcpResource{
		{
			URI:         "mgtls://store/manifest",
			Name:        "mgtls Cryptographic Store Manifest",
			Description: "Complete inventory of Root/Intermediate CAs, X.509 certificates, OpenSSH CAs/certs, ACME orders, and target bundles",
			MimeType:    "application/json",
		},
		{
			URI:         "mgtls://targets/catalog",
			Name:        "Supported Target Frameworks Catalog",
			Description: "Catalog of supported TLS/mTLS and SSH target frameworks (FastAPI, Spring Boot, MCP, NGINX, Vite, Proxmox, OpenSSH)",
			MimeType:    "application/json",
		},
		{
			URI:         "mgtls://acme/providers",
			Name:        "Supported Free ACME v2 Providers",
			Description: "Directory URLs and EAB requirements for Let's Encrypt, ZeroSSL, Buypass, and Google Trust Services",
			MimeType:    "application/json",
		},
	}
}

func (srv *Server) readResource(uri string) ([]mcpResourceContents, error) {
	switch uri {
	case "mgtls://store/manifest":
		m, err := srv.Store.LoadManifest()
		if err != nil {
			return nil, err
		}
		raw, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return nil, err
		}
		return []mcpResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(raw),
		}}, nil

	case "mgtls://targets/catalog":
		raw, err := json.MarshalIndent(targets.SupportedTargets(), "", "  ")
		if err != nil {
			return nil, err
		}
		return []mcpResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(raw),
		}}, nil

	case "mgtls://acme/providers":
		raw, err := json.MarshalIndent(acme.ListProviders(), "", "  ")
		if err != nil {
			return nil, err
		}
		return []mcpResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(raw),
		}}, nil

	default:
		return nil, fmt.Errorf("resource not found: %s", uri)
	}
}

func (srv *Server) listPrompts() []mcpPrompt {
	return []mcpPrompt{
		{
			Name:        "setup-mtls-service",
			Description: "Guided workflow to provision a Root CA, Server & Client mTLS certificates, and target bundle for FastAPI, Spring Boot, MCP, NGINX, or Vite",
			Arguments: []mcpPromptArgument{
				{Name: "target_type", Description: "fastapi, springboot, mcp, nginx, or vite", Required: true},
				{Name: "service_name", Description: "Logical service name", Required: true},
				{Name: "domain", Description: "Primary DNS hostname (e.g. api.internal)", Required: false},
			},
		},
		{
			Name:        "setup-ssh-ca",
			Description: "Guided workflow to deploy OpenSSH User & Host Certificate Authorities, sign certificates, and generate sshd_config/ssh_config bundles",
			Arguments: []mcpPromptArgument{
				{Name: "environment", Description: "Environment name (e.g. prod, homelab)", Required: false},
				{Name: "principals", Description: "Comma-separated SSH principals (e.g. root,admin)", Required: false},
			},
		},
		{
			Name:        "setup-proxmox-tls",
			Description: "Guided workflow to issue and deploy a trusted TLS/ACME certificate to a Proxmox VE node (pveproxy)",
			Arguments: []mcpPromptArgument{
				{Name: "node_fqdn", Description: "Proxmox node FQDN (e.g. pve1.homelab.internal)", Required: true},
				{Name: "node_ip", Description: "Proxmox node IPv4 address", Required: false},
			},
		},
	}
}

func (srv *Server) getPrompt(name string, args map[string]string) (string, []mcpPromptMessage, error) {
	switch name {
	case "setup-mtls-service":
		target := args["target_type"]
		if target == "" {
			target = "fastapi"
		}
		svc := args["service_name"]
		if svc == "" {
			svc = "my-service"
		}
		domain := args["domain"]
		if domain == "" {
			domain = "localhost"
		}
		text := fmt.Sprintf(
			"Provision end-to-end mutual TLS (mTLS) for %s (%s on %s):\n"+
				"1. Call `pki_create_ca` with `name: \"%s-ca\"`.\n"+
				"2. Call `pki_issue_cert` with `name: \"%s-server\"`, `ca_name: \"%s-ca\"`, `role: \"server\"`, `dns_names: [\"%s\", \"localhost\"]`, `ip_addresses: [\"127.0.0.1\"]`.\n"+
				"3. Call `pki_issue_cert` with `name: \"%s-client\"`, `ca_name: \"%s-ca\"`, `role: \"client\"`.\n"+
				"4. Call `target_generate` with `name: \"%s\"`, `target_type: \"%s\"`, `mutual_tls: true`, `ca_name: \"%s-ca\"`, `server_cert: \"%s-server\"`, `client_cert: \"%s-client\"`, `host: \"%s\"`.\n"+
				"5. Call `pki_verify` to confirm chain and EKU validity.",
			svc, target, domain,
			svc,
			svc, svc, domain,
			svc, svc,
			svc, target, svc, svc, svc, domain,
		)
		return "End-to-end mTLS provisioning workflow", []mcpPromptMessage{{
			Role:    "user",
			Content: mcpContent{Type: "text", Text: text},
		}}, nil

	case "setup-ssh-ca":
		env := args["environment"]
		if env == "" {
			env = "fleet"
		}
		principals := args["principals"]
		if principals == "" {
			principals = "root,admin"
		}
		text := fmt.Sprintf(
			"Provision OpenSSH User and Host Certificate Authorities for %s:\n"+
				"1. Call `ssh_create_ca` with `name: \"%s-user-ca\"`, `ca_type: \"user\"`.\n"+
				"2. Call `ssh_create_ca` with `name: \"%s-host-ca\"`, `ca_type: \"host\"`.\n"+
				"3. Call `ssh_sign_cert` for user identity (`principals: [%q]`) and host identity.\n"+
				"4. Call `ssh_config_bundle` to generate `sshd_config`, `ssh_config`, `known_hosts`, and `authorized_principals`.",
			env, env, env, principals,
		)
		return "OpenSSH User & Host CA rollout workflow", []mcpPromptMessage{{
			Role:    "user",
			Content: mcpContent{Type: "text", Text: text},
		}}, nil

	case "setup-proxmox-tls":
		fqdn := args["node_fqdn"]
		if fqdn == "" {
			fqdn = "pve.internal"
		}
		ip := args["node_ip"]
		if ip == "" {
			ip = "127.0.0.1"
		}
		text := fmt.Sprintf(
			"Provision and deploy TLS certificate for Proxmox VE node %s (%s):\n"+
				"1. Call `pki_create_ca` with `name: \"proxmox-ca\"` (or use `acme_obtain` for public DNS).\n"+
				"2. Call `pki_issue_cert` with `name: \"pve-node\"`, `ca_name: \"proxmox-ca\"`, `role: \"server\"`, `dns_names: [\"%s\", \"localhost\"]`, `ip_addresses: [\"%s\", \"127.0.0.1\"]`.\n"+
				"3. Call `target_generate` with `target_type: \"proxmox\"`, `host: \"%s\"`, `ca_name: \"proxmox-ca\"`, `server_cert: \"pve-node\"`.",
			fqdn, ip, fqdn, ip, fqdn,
		)
		return "Proxmox VE TLS deployment workflow", []mcpPromptMessage{{
			Role:    "user",
			Content: mcpContent{Type: "text", Text: text},
		}}, nil

	default:
		return "", nil, fmt.Errorf("prompt not found: %s", name)
	}
}

// ServeStdio runs a newline-delimited JSON-RPC 2.0 loop over in and out until EOF or context cancellation.
func (srv *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		resp, err := srv.HandleJSONRPC(ctx, []byte(line))
		if err != nil {
			return err
		}
		if len(resp) > 0 {
			if _, err := fmt.Fprintf(out, "%s\n", resp); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

// NewHTTPHandler returns an http.Handler serving MCP JSON-RPC 2.0 over POST / and POST /mcp plus GET /healthz.
func (srv *Server) NewHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"mgtls-mcp"}`))
	})
	handleRPC := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"mgtls","protocolVersion":"2024-11-05","status":"ready"}`))
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := srv.HandleJSONRPC(r.Context(), body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(resp) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}
	mux.HandleFunc("/", handleRPC)
	mux.HandleFunc("/mcp", handleRPC)
	return mux
}

// ServeHTTP starts an HTTP, HTTPS, or mutual-TLS (mTLS) MCP server on addr.
func (srv *Server) ServeHTTP(ctx context.Context, addr, certFile, keyFile, clientCAFile string) error {
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.NewHTTPHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if certFile != "" && keyFile != "" {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if clientCAFile != "" {
			caPEM, err := os.ReadFile(clientCAFile)
			if err != nil {
				return fmt.Errorf("read client CA %s: %w", clientCAFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return fmt.Errorf("failed to parse client CA PEM %s", clientCAFile)
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		httpSrv.TLSConfig = tlsCfg
	}

	errCh := make(chan error, 1)
	go func() {
		if certFile != "" && keyFile != "" {
			errCh <- httpSrv.ListenAndServeTLS(certFile, keyFile)
		} else {
			errCh <- httpSrv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
