package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditGenesisHash is the prev_hash of the first ledger entry.
const AuditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Audit event names.
const (
	AuditCACreate    = "ca.create"
	AuditCertIssue   = "cert.issue"
	AuditCertSelf    = "cert.self_sign"
	AuditCSRSign     = "csr.sign"
	AuditESTEnroll   = "est.enroll"
	AuditCertRevoke  = "cert.revoke"
	AuditVaultSeal   = "vault.seal"
	AuditVaultUnseal = "vault.unseal"
	AuditVaultRotate = "vault.rotate"
)

// AuditEntry is one record of the SHA-256 hash-chained, append-only ledger.
// Hash = SHA-256 of the JSON encoding of the entry with Hash cleared.
type AuditEntry struct {
	Seq      uint64            `json:"seq"`
	Time     string            `json:"time"`
	Event    string            `json:"event"`
	Subject  string            `json:"subject,omitempty"`
	Actor    string            `json:"actor,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// AuditReport is the result of VerifyAudit.
type AuditReport struct {
	Valid     bool   `json:"valid"`
	Entries   int    `json:"entries"`
	HeadHash  string `json:"head_hash"`
	BrokenSeq uint64 `json:"broken_seq,omitempty"`
	Error     string `json:"error,omitempty"`
}

var auditMu sync.Mutex // serializes appends within one process (single-writer ledger)

// AuditPath is the ledger location (<store>/audit.jsonl).
func (s *Store) AuditPath() string { return s.Path("audit.jsonl") }

func (e AuditEntry) computeHash() string {
	e.Hash = ""
	b, _ := json.Marshal(e) // struct field order + sorted map keys => deterministic
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readAudit(path string) ([]AuditEntry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []AuditEntry
	r := bufio.NewReader(f)
	for line := 1; ; line++ {
		raw, rErr := r.ReadBytes('\n')
		if t := strings.TrimSpace(string(raw)); t != "" {
			var e AuditEntry
			if err := json.Unmarshal([]byte(t), &e); err != nil {
				return out, fmt.Errorf("audit line %d: %w", line, err)
			}
			out = append(out, e)
		}
		if rErr == io.EOF {
			return out, nil
		}
		if rErr != nil {
			return out, rErr
		}
	}
}

// Audit appends a hash-chained entry. Callers treat failures as non-fatal to the
// audited operation, but the error is returned so it is never silently lost.
func (s *Store) Audit(event, subject string, details map[string]string) error {
	if err := s.Init(); err != nil {
		return err
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	entries, err := readAudit(s.AuditPath())
	if err != nil {
		return fmt.Errorf("audit ledger unreadable (refusing to append): %w", err)
	}
	e := AuditEntry{Seq: 1, Time: time.Now().UTC().Format(time.RFC3339Nano), Event: event, Subject: subject, Details: details, PrevHash: AuditGenesisHash}
	if u := os.Getenv("USER"); u != "" {
		e.Actor = u
	}
	if n := len(entries); n > 0 {
		e.Seq, e.PrevHash = entries[n-1].Seq+1, entries[n-1].Hash
	}
	e.Hash = e.computeHash()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.AuditPath()), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.AuditPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// ListAudit returns ledger entries, optionally filtered by event and limited to the last n (n<=0: all).
func (s *Store) ListAudit(event string, last int) ([]AuditEntry, error) {
	entries, err := readAudit(s.AuditPath())
	if err != nil {
		return nil, err
	}
	if event != "" {
		f := entries[:0:0]
		for _, e := range entries {
			if e.Event == event {
				f = append(f, e)
			}
		}
		entries = f
	}
	if last > 0 && len(entries) > last {
		entries = entries[len(entries)-last:]
	}
	return entries, nil
}

// VerifyAudit recomputes the whole chain. expectHead, if non-empty, pins the head hash so
// tail truncation (undetectable from the file alone) is also caught.
func (s *Store) VerifyAudit(expectHead string) (*AuditReport, error) {
	entries, err := readAudit(s.AuditPath())
	rep := &AuditReport{Valid: true, HeadHash: AuditGenesisHash}
	bad := func(seq uint64, f string, a ...any) (*AuditReport, error) {
		rep.Valid, rep.BrokenSeq, rep.Error = false, seq, fmt.Sprintf(f, a...)
		return rep, nil
	}
	prev := AuditGenesisHash
	for i, e := range entries {
		rep.Entries = i + 1
		if e.Seq != uint64(i+1) {
			return bad(e.Seq, "sequence gap or reorder: expected %d, got %d", i+1, e.Seq)
		}
		if e.PrevHash != prev {
			return bad(e.Seq, "prev_hash mismatch (entry removed, inserted, or reordered)")
		}
		if e.Hash != e.computeHash() {
			return bad(e.Seq, "hash mismatch (entry modified)")
		}
		prev, rep.HeadHash = e.Hash, e.Hash
	}
	if err != nil {
		return bad(uint64(len(entries)+1), "%v", err)
	}
	if expectHead = strings.TrimSpace(expectHead); expectHead != "" && !strings.EqualFold(expectHead, rep.HeadHash) {
		return bad(uint64(len(entries)), "head hash %s does not match pinned %s (ledger truncated or rewritten)", rep.HeadHash, expectHead)
	}
	return rep, nil
}
