package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"selfdiag.local/rebuild/internal/model"
)

func TestEvidenceIsHTMLEscaped(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report")
	r := model.Report{Rules: []model.RuleResult{{Evidence: []model.Evidence{{Text: "<script>alert(1)</script>"}}}}}
	if err := Write(out, r); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "<script>") || !strings.Contains(string(b), "&lt;script&gt;") {
		t.Fatal("evidence HTML not escaped")
	}
}
