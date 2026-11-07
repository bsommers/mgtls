package profile

import (
	"os"
	"strings"
	"testing"

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
	rep, err := RunRenewalCycle(t.Context(), s, spec, 0, "")
	if err == nil {
		t.Fatal("expected aggregated error for bad item")
	}
	if rep == nil || len(rep.RenewedSelfSigned) != 1 || rep.RenewedSelfSigned[0] != "good" || len(rep.Errors) != 1 {
		t.Fatalf("cycle did not continue past failure: %+v", rep)
	}
}
