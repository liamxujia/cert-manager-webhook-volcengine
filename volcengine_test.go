package volcengine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewValidatesAndCopiesAllowlist(t *testing.T) {
	dir := t.TempDir()
	access, secret := filepath.Join(dir, "access"), filepath.Join(dir, "secret")
	for _, path := range []string{access, secret} {
		if err := os.WriteFile(path, []byte("test-key"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files := CredentialFiles{AccessKeyPath: access, SecretKeyPath: secret}
	cfg := Config{JournalNamespace: "cert-manager", JournalName: "journal", AllowedNamespaces: []string{"cert-manager"}, Targets: []Target{{FQDN: "apps.acme.example.com.", Zone: "acme.example.com.", ZoneID: 123, Project: "test-acme"}}}
	s, err := New(cfg, files)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "volcengine" {
		t.Fatalf("unexpected solver name %q", s.Name())
	}
	cfg.AllowedNamespaces[0] = "other"
	cfg.Targets[0].FQDN = "other.acme.example.com."
	if !s.inner.Config.AllowedNamespaces["cert-manager"] || s.inner.Config.AllowedNamespaces["other"] || s.inner.Config.Targets["apps.acme.example.com."].FQDN != "apps.acme.example.com." {
		t.Fatal("caller mutation changed solver allowlist")
	}
	cfg.AllowedNamespaces = []string{"cert-manager,other"}
	if _, err := New(cfg, files); err == nil {
		t.Fatal("accepted a comma-separated namespace as one entry")
	}
	cfg.AllowedNamespaces = []string{"cert-manager"}
	cfg.Targets[0].Project = "default"
	if _, err := New(cfg, files); err == nil {
		t.Fatal("accepted the default project")
	}
	cfg.Targets[0].Project = "test-acme"
	if _, err := New(cfg, CredentialFiles{}); err == nil {
		t.Fatal("accepted missing credential files")
	}
}

func TestZeroSolverFailsClosed(t *testing.T) {
	var s Solver
	if s.Name() != "volcengine" || s.Initialize(nil, nil) == nil || s.Present(nil) == nil || s.CleanUp(nil) == nil {
		t.Fatal("unconstructed solver must reject operations")
	}
}
