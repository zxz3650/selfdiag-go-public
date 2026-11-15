//go:build linux || darwin

package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"selfdiag.local/rebuild/internal/evidence"
	"selfdiag.local/rebuild/internal/model"
)

func put(t *testing.T, root, path, body string) {
	t.Helper()
	p := filepath.Join(root, relative(path))
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func lookup(t *testing.T, m model.Manifest, source string) model.Artifact {
	t.Helper()
	for _, a := range m.Artifacts {
		if a.Source == source {
			return a
		}
	}
	t.Fatalf("missing source %s", source)
	return model.Artifact{}
}
func collectFixture(t *testing.T, root, osName string, opts Options) (model.Manifest, map[string][]byte) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle")
	opts.SourceRoot = root
	opts.SourceOS = osName
	opts.Profile = "extended"
	opts.Timeout = time.Second
	if err := CollectWithOptions(out, opts); err != nil {
		t.Fatal(err)
	}
	m, b, _, err := evidence.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	return m, b
}

func TestExtendedLinuxArtifactsAndNoLiveCommands(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		"/etc/passwd":      "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
		"/etc/cron.d/demo": "* * * * * root /bin/true\n", "/etc/systemd/system/demo.service": "[Service]\nExecStart=/bin/true\n",
		"/var/log/auth.log.1": "Sep 29 10:00:00 host sshd: Failed password for root from 192.0.2.1\n", "/var/log/auth.log.2.gz": "compressed bytes",
		"/home/alice/.bash_history": "nmap 192.0.2.1\n", "/home/alice/.profile": "export LANG=C\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n", "/var/www/html/index.php": "<?php echo 1;",
		"/proc/123/status": "Name:\ttest\n", "/proc/123/maps": "/lib/demo.so\n",
		"/etc/shadow": "TEST SECRET", "/proc/123/environ": "TEST_TOKEN=demo", "/bin/demo": "inert fixture",
	} {
		put(t, root, path, body)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc/123/fd"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"exe": "/bin/demo", "cwd": "/root", "root": "/", "fd/3": "socket:[123]"} {
		if err := os.Symlink(target, filepath.Join(root, "proc/123", name)); err != nil {
			t.Fatal(err)
		}
	}
	m, data := collectFixture(t, root, "linux", Options{})
	for _, path := range []string{"/etc/cron.d/demo", "/etc/systemd/system/demo.service", "/var/log/auth.log.1", "/home/alice/.bash_history", "/etc/ssh/sshd_config", "/var/www/html/index.php", "/proc/123/status"} {
		a := lookup(t, m, path)
		if a.Status != "collected" || len(data[a.ID]) == 0 {
			t.Fatalf("not collected: %+v", a)
		}
	}
	if lookup(t, m, "/var/log/auth.log.2.gz").Kind != "compressed_log" {
		t.Fatal("compressed log treated as text")
	}
	for _, a := range m.Artifacts {
		if strings.HasPrefix(a.Source, "[") && (a.Status != "unsupported" || !strings.Contains(a.Detail, "disabled")) {
			t.Fatal("fixture executed live command")
		}
		if a.Source == "/etc/shadow" || a.Source == "/proc/123/environ" || a.Kind == "executable" {
			t.Fatal("sensitive optional artifact collected by default")
		}
	}
	a := lookup(t, m, "/proc/123/{exe,cwd,root,fd}")
	if !strings.Contains(string(data[a.ID]), "socket:[123]") {
		t.Fatal("fd correlation missing")
	}
	m, _ = collectFixture(t, root, "linux", Options{IncludeSensitive: true, IncludeBinaries: true})
	for _, path := range []string{"/etc/shadow", "/proc/123/environ", "/bin/demo"} {
		if lookup(t, m, path).Status != "collected" {
			t.Fatalf("optional artifact %s missing", path)
		}
	}
}

func TestExtendedDarwinPersistenceAndBrowser(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{"/Library/LaunchDaemons/example.plist": "<plist/>", "/Users/alice/.zsh_history": "ls\n", "/Users/alice/Library/LaunchAgents/user.plist": "<plist/>", "/Users/alice/Library/Safari/History.db": "sqlite fixture"} {
		put(t, root, path, body)
	}
	m, _ := collectFixture(t, root, "darwin", Options{IncludeBrowser: true})
	for _, path := range []string{"/Library/LaunchDaemons/example.plist", "/Users/alice/.zsh_history", "/Users/alice/Library/LaunchAgents/user.plist", "/Users/alice/Library/Safari/History.db"} {
		if lookup(t, m, path).Status != "collected" {
			t.Fatalf("not collected: %s", path)
		}
	}
}

func TestSourceRootConfinesSymlinkParents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	put(t, outside, "/sshd_config", "OUTSIDE SECRET")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc/ssh")); err != nil {
		t.Fatal(err)
	}
	m, data := collectFixture(t, root, "linux", Options{})
	for _, b := range data {
		if strings.Contains(string(b), "OUTSIDE SECRET") {
			t.Fatal("source root escaped")
		}
	}
	if lookup(t, m, "/etc/ssh").Status != "unsupported" {
		t.Fatal("symlink directory followed")
	}
}

func TestCollectionBudgetPreservesValidManifest(t *testing.T) {
	root := t.TempDir()
	for i := 1; i <= 90; i++ {
		put(t, root, fmt.Sprintf("/proc/%d/status", i), "test\n")
	}
	out := filepath.Join(t.TempDir(), "bundle")
	err := CollectWithOptions(out, Options{Profile: "extended", Timeout: time.Second, SourceRoot: root, SourceOS: "linux", MaxProcesses: 128})
	if !errors.Is(err, evidence.ErrBudget) {
		t.Fatalf("expected budget error, got %v", err)
	}
	m, _, _, err := evidence.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.CollectionStatus != "limited" || len(m.CollectionNotes) == 0 || len(m.Artifacts) != evidence.MaxFiles {
		t.Fatalf("invalid limited manifest: %+v", m)
	}
}

func TestTreeLimitAndOutputExclusion(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 80; i++ {
		put(t, root, fmt.Sprintf("/var/log/item-%03d.log", i), "log\n")
	}
	out := filepath.Join(root, "var/log/result")
	err := CollectWithOptions(out, Options{Profile: "extended", Timeout: time.Second, SourceRoot: root, SourceOS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _, err := evidence.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.CollectionStatus != "limited" {
		t.Fatal("tree truncation unreported")
	}
	for _, a := range m.Artifacts {
		if strings.HasPrefix(a.Source, "/var/log/result/") {
			t.Fatal("collected own output")
		}
	}
}

func TestPlanIncludesExpandedCategories(t *testing.T) {
	for _, osName := range []string{"linux", "darwin"} {
		p, err := Plan(osName, "extended")
		if err != nil {
			t.Fatal(err)
		}
		if len(p["commands"].([]map[string]any)) < 15 || len(p["trees"].([]treeSpec)) < 5 {
			t.Fatalf("incomplete plan for %s", osName)
		}
	}
}
