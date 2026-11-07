package profile

import (
	"os"
	"strings"
	"testing"

	"github.com/sysadmin/mgtls/src/pkg/pki"
	"github.com/sysadmin/mgtls/src/pkg/store"
)

func TestSystemdUnitsRejectInjectionAndQuoteSpecifiers(t *testing.T) {
	s, _ := store.New(t.TempDir())
	out := t.TempDir()
	bad := []SystemdRequest{
		{UnitName: "x\nExecStartPre=/bin/sh", OutputDir: out},
		{UnitName: "../../etc/systemd/system/evil", OutputDir: out},
		{Calendar: "daily\nUser=root", OutputDir: out},
		{RenewBefore: "720h\nUser=root", OutputDir: out},
		{OnRenewHook: "reload\nExecStartPost=/bin/sh", OutputDir: out},
		{BinaryPath: "mgtls", OutputDir: out},
	}
	for i, req := range bad {
		if _, err := GenerateSystemdUnits(s, req); err == nil {
			t.Errorf("case %d accepted: %+v", i, req)
		}
	}
	b, err := GenerateSystemdUnits(s, SystemdRequest{OnRenewHook: `systemctl reload nginx && echo "$HOME %h"`, OutputDir: out})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(b.ServicePath)
	if !strings.Contains(string(raw), `"systemctl reload nginx && echo \"$$HOME %%h\""`) {
		t.Errorf("hook not systemd-quoted:\n%s", raw)
	}
	if !strings.Contains(string(raw), "NoNewPrivileges=true") {
		t.Error("NoNewPrivileges missing")
	}
}

func TestRenewalCycleContinuesPastFailingItem(t *testing.T) {
	s, _ := store.New(t.TempDir())
	spec, err := ParseFleetSpec([]byte(`{"self_signed":[{"name":"bad/name"},{"name":"good","common_name":"good.internal"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunRenewalCycle(t.Context(), s, spec, 0, "", false)
	if err == nil {
		t.Fatal("expected aggregated error for bad item")
	}
	if rep == nil || len(rep.RenewedSelfSigned) != 1 || rep.RenewedSelfSigned[0] != "good" || len(rep.Errors) != 1 {
		t.Fatalf("cycle did not continue past failure: %+v", rep)
	}
}

func TestRenewalCycleHonorsRevocationUnlessOptedIn(t *testing.T) {
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ParseFleetSpec([]byte(`{
		"cas":[{"name":"rca","common_name":"Revoke CA"}],
		"certs":[{"name":"leaf","common_name":"leaf.internal","ca_name":"rca","valid_days":365}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), s, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := pki.RevokeCert(s, "rca", "leaf", 1); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	// Default, both spec and store-only mode: revocation is honored.
	for _, sp := range []*FleetSpec{spec, nil} {
		rep, err := RunRenewalCycle(t.Context(), s, sp, 0, "", false)
		if err != nil {
			t.Fatalf("cycle (spec=%v): %v", sp != nil, err)
		}
		if len(rep.RenewedCerts) != 0 || len(rep.SkippedRevoked) != 1 || rep.SkippedRevoked[0] != "leaf" {
			t.Fatalf("revoked cert not honored (spec=%v): %+v", sp != nil, rep)
		}
		c, err := s.GetCert("leaf")
		if err != nil || !c.Revoked {
			t.Fatalf("leaf no longer revoked (spec=%v): %+v %v", sp != nil, c, err)
		}
	}

	// Opt-in rotation: the revoked cert is reissued and the new record is live.
	rep, err := RunRenewalCycle(t.Context(), s, spec, 0, "", true)
	if err != nil {
		t.Fatalf("cycle with reissue: %v", err)
	}
	if len(rep.RenewedCerts) != 1 || len(rep.SkippedRevoked) != 0 {
		t.Fatalf("revoked cert not rotated: %+v", rep)
	}
	if c, err := s.GetCert("leaf"); err != nil || c.Revoked {
		t.Fatalf("rotated leaf still revoked: %+v %v", c, err)
	}
}

func TestSystemdUnitReissueRevokedFlag(t *testing.T) {
	s, _ := store.New(t.TempDir())
	for _, want := range []bool{false, true} {
		b, err := GenerateSystemdUnits(s, SystemdRequest{OutputDir: t.TempDir(), ReissueRevoked: want})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(b.ServicePath)
		if got := strings.Contains(string(raw), "--reissue-revoked"); got != want {
			t.Errorf("ReissueRevoked=%v: flag present=%v\n%s", want, got, raw)
		}
	}
}
