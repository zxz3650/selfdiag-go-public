package detector

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"selfdiag.local/rebuild/internal/evidence"
	"selfdiag.local/rebuild/internal/model"
)

func bundle(t *testing.T, osName, auth, history string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "bundle")
	w, err := evidence.New(root, osName, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []struct{ path, kind, data string }{{"/var/log/auth.log", "auth", auth}, {"/root/.bash_history", "history", history}} {
		if err := w.Add(a.path, a.kind, "collected", "", []byte(a.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	return root
}

func failures(n int) string {
	var s strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&s, "Sep 29 12:01:%02d host sshd[1]: Failed password for root from 192.0.2.50 port 4242 ssh2\n", i)
	}
	return s.String()
}

func TestBaselineAndIndicators(t *testing.T) {
	for _, tc := range []struct {
		name, auth, history string
		want                int
	}{{"baseline", "", "whoami\nuptime\n", 0}, {"indicators", failures(20), "nmap -sV 192.0.2.20\nsystemctl enable lab-demo.service\n", 3}} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Analyze(bundle(t, "linux", tc.auth, tc.history))
			if err != nil {
				t.Fatal(err)
			}
			if r.Counts["matched"] != tc.want || r.Counts["unsupported"] != 33 || r.Counts["evaluated"] != 3 {
				t.Fatalf("wrong counts: %v", r.Counts)
			}
			for _, rule := range r.Rules {
				if rule.Verdict == "matched" && len(rule.Evidence) == 0 {
					t.Fatal("match without provenance")
				}
			}
		})
	}
}

func TestLoginBoundaryAndUnsortedTimestamps(t *testing.T) {
	for _, tc := range []struct {
		n, span int
		want    bool
	}{{14, 14, false}, {15, 59, true}, {15, 60, true}, {15, 61, false}, {16, 16, true}} {
		lines := []string{}
		start := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
		for i := 0; i < tc.n; i++ {
			seconds := i
			if i == tc.n-1 {
				seconds = tc.span
			}
			lines = append([]string{start.Add(time.Duration(seconds)*time.Second).Format("Jan _2 15:04:05") + " host sshd: Failed password for root from 192.0.2.1"}, lines...)
		}
		refs, complete := loginMatches(model.Artifact{ID: "a1"}, lines, 2026)
		if (len(refs) > 0) != tc.want || !complete {
			t.Fatalf("n=%d span=%d matches=%d complete=%v", tc.n, tc.span, len(refs), complete)
		}
	}
}

func TestUnparsedTimestampIsUnknown(t *testing.T) {
	r, err := Analyze(bundle(t, "linux", "bad date Failed password for root from 192.0.2.1", ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range r.Rules {
		if rule.ID == LoginID && (rule.Verdict != "unknown" || rule.Coverage != "partial") {
			t.Fatalf("unparsed input considered clean: %+v", rule)
		}
	}
}

func TestSourceOSIsNotAnalyzerOS(t *testing.T) {
	r, err := Analyze(bundle(t, "darwin", failures(20), "nmap 192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Counts["matched"] != 0 || r.Counts["skipped"] != 36 {
		t.Fatalf("Linux rules applied to macOS: %v", r.Counts)
	}
}

func TestMissingEvidenceNotClean(t *testing.T) {
	root := filepath.Join(t.TempDir(), "empty")
	w, err := evidence.New(root, "linux", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Save(); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if r.Counts["not_matched"] != 0 || r.Counts["skipped"] != 3 {
		t.Fatalf("missing inputs considered clean: %v", r.Counts)
	}
}
