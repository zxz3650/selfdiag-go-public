package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"selfdiag.local/rebuild/internal/model"
)

const MaxFile = 8 * 1024 * 1024
const MaxFiles = 512
const MaxTotal = 64 * 1024 * 1024

var ErrBudget = errors.New("evidence budget exceeded")

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func NewDir(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.Mkdir(path, 0700) // Never overwrite an existing bundle/report.
}

func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

type Writer struct {
	Root     string
	Manifest model.Manifest
	total    int64
}

func New(root, sourceOS, arch, mode string) (*Writer, error) {
	if sourceOS != "linux" && sourceOS != "darwin" {
		return nil, fmt.Errorf("source OS must be linux or darwin")
	}
	if err := NewDir(root); err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(root, "artifacts"), 0700); err != nil {
		return nil, err
	}
	return &Writer{Root: root, Manifest: model.Manifest{Schema: model.Schema, SourceOS: sourceOS, SourceArch: arch,
		CollectorOS: runtime.GOOS, CollectorArch: runtime.GOARCH, Started: time.Now().UTC(), Mode: mode, Artifacts: []model.Artifact{}}}, nil
}

func (w *Writer) Add(source, kind, status, detail string, data []byte) error {
	if status == "collected" && data == nil {
		data = []byte{}
	}
	if len(w.Manifest.Artifacts) >= MaxFiles {
		return fmt.Errorf("%w: artifact count", ErrBudget)
	}
	if len(data) > MaxFile || w.total+int64(len(data)) > MaxTotal {
		return fmt.Errorf("%w: byte count", ErrBudget)
	}
	a := model.Artifact{ID: fmt.Sprintf("a%04d", len(w.Manifest.Artifacts)+1), Source: source, Kind: kind, Status: status, Detail: detail, CapturedUTC: time.Now().UTC()}
	if data != nil {
		a.Path = "artifacts/" + a.ID
		a.SHA256 = Hash(data)
		a.Bytes = int64(len(data))
		if err := os.WriteFile(filepath.Join(w.Root, filepath.FromSlash(a.Path)), data, 0600); err != nil {
			return err
		}
		w.total += a.Bytes
	}
	w.Manifest.Artifacts = append(w.Manifest.Artifacts, a)
	return nil
}

func (w *Writer) File(path, source, kind string) error {
	return w.file(path, source, kind, os.Lstat, os.Open)
}

// FileAt confines all path resolution to a source root, including parent symlinks.
func (w *Writer) FileAt(root *os.Root, path, source, kind string) error {
	return w.file(path, source, kind, root.Lstat, root.Open)
}

func (w *Writer) file(path, source, kind string, lstat func(string) (os.FileInfo, error), open func(string) (*os.File, error)) error {
	info, err := lstat(path)
	if err != nil {
		status := "error"
		if os.IsNotExist(err) {
			status = "missing"
		}
		if os.IsPermission(err) {
			status = "permission_denied"
		}
		return w.Add(source, kind, status, err.Error(), nil)
	}
	if !info.Mode().IsRegular() {
		return w.Add(source, kind, "unsupported", "not a regular file; symlinks not followed", nil)
	}
	f, err := open(path)
	if err != nil {
		status := "error"
		if os.IsPermission(err) {
			status = "permission_denied"
		}
		return w.Add(source, kind, status, err.Error(), nil)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return w.Add(source, kind, "error", err.Error(), nil)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return w.Add(source, kind, "error", "source changed between inspection and open", nil)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil {
		return w.Add(source, kind, "error", err.Error(), nil)
	}
	status, detail := "collected", ""
	if len(b) > MaxFile {
		b = b[:MaxFile]
		status = "truncated"
		detail = "file byte limit"
	}
	if after, e := f.Stat(); e != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		status = "partial"
		detail = "file changed while reading"
	}
	if err := w.Add(source, kind, status, detail, b); err != nil {
		return err
	}
	a := &w.Manifest.Artifacts[len(w.Manifest.Artifacts)-1]
	size := info.Size()
	modified := info.ModTime().UTC()
	a.SourceSize = &size
	a.SourceMode = info.Mode().String()
	a.SourceModifiedUTC = &modified
	return nil
}

func (w *Writer) Save() error { return WriteJSON(filepath.Join(w.Root, "manifest.json"), w.Manifest) }

func Classify(path string) string {
	b := filepath.Base(path)
	for _, suffix := range []string{".gz", ".xz", ".bz2", ".zst"} {
		if strings.HasSuffix(b, suffix) {
			return "compressed_log"
		}
	}
	if b == "auth.log" || strings.HasPrefix(b, "auth.log.") || b == "secure" || strings.HasPrefix(b, "secure.") {
		return "auth"
	}
	if b == ".bash_history" || b == ".zsh_history" || b == ".history" || b == ".sh_history" || b == ".ksh_history" || b == ".tcsh_history" {
		return "history"
	}
	if b == "syslog" || b == "cron" || b == "daemon.log" || b == "journal_dmp" || strings.HasPrefix(b, "syslog.") || strings.HasPrefix(b, "cron.") || strings.HasPrefix(b, "daemon.log.") {
		return "event_log"
	}
	return "other"
}

// Import copies regular files only, using generated artifact names instead of source paths.
func Import(root, out, sourceOS string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("import root must be a directory")
	}
	outAbs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(outAbs))
	if err != nil {
		return fmt.Errorf("output parent must exist: %w", err)
	}
	outAbs = filepath.Join(parent, filepath.Base(outAbs))
	rel, err := filepath.Rel(root, outAbs)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return fmt.Errorf("output must be outside import root")
	}
	w, err := New(outAbs, sourceOS, "unknown", "import")
	if err != nil {
		return err
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		return w.File(path, filepath.ToSlash(rel), Classify(path))
	})
	if err != nil {
		return err
	}
	return w.Save()
}

// Load rejects path traversal, symlinks, duplicate IDs/paths, and modified data.
func Load(root string) (model.Manifest, map[string][]byte, string, error) {
	var m model.Manifest
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return m, nil, "", err
	}
	defer rootFS.Close()
	read := func(path string, limit int64) ([]byte, error) {
		f, e := rootFS.Open(path)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, limit+1))
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("oversized %s", path)
		}
		return b, e
	}
	b, err := read("manifest.json", 2*1024*1024)
	if err != nil {
		return m, nil, "", err
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return m, nil, "", err
	}
	if m.Schema != model.Schema || (m.SourceOS != "linux" && m.SourceOS != "darwin") || len(m.Artifacts) > MaxFiles || m.Started.IsZero() {
		return m, nil, "", fmt.Errorf("invalid manifest")
	}
	data := map[string][]byte{}
	ids := map[string]bool{}
	paths := map[string]bool{}
	var total int64
	for _, a := range m.Artifacts {
		if a.ID == "" || ids[a.ID] {
			return m, nil, "", fmt.Errorf("duplicate/empty artifact ID")
		}
		ids[a.ID] = true
		switch a.Status {
		case "collected", "missing", "permission_denied", "timeout", "truncated", "partial", "error", "unsupported":
		default:
			return m, nil, "", fmt.Errorf("invalid status %q", a.Status)
		}
		if a.Path == "" {
			if a.Status == "collected" || a.Bytes != 0 || a.SHA256 != "" {
				return m, nil, "", fmt.Errorf("artifact has no data: %s", a.ID)
			}
			continue
		}
		if !strings.HasPrefix(a.Path, "artifacts/") || strings.Contains(a.Path, "\\") || strings.Contains(a.Path, "..") || paths[a.Path] {
			return m, nil, "", fmt.Errorf("invalid artifact path")
		}
		paths[a.Path] = true
		info, e := rootFS.Lstat(a.Path)
		if e != nil {
			return m, nil, "", e
		}
		if !info.Mode().IsRegular() {
			return m, nil, "", fmt.Errorf("non-regular artifact")
		}
		content, e := read(a.Path, MaxFile)
		if e != nil {
			return m, nil, "", e
		}
		total += int64(len(content))
		if total > MaxTotal {
			return m, nil, "", fmt.Errorf("total size exceeded")
		}
		if int64(len(content)) != a.Bytes || Hash(content) != a.SHA256 {
			return m, nil, "", fmt.Errorf("integrity mismatch: %s", a.ID)
		}
		data[a.ID] = content
	}
	return m, data, Hash(b), nil
}
