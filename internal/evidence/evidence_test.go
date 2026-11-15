package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) *Writer {
	t.Helper()
	w, err := New(filepath.Join(t.TempDir(), "bundle"), "linux", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Add("auth.log", "auth", "collected", "", []byte("sample")); err != nil {
		t.Fatal(err)
	}
	if err = w.Save(); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestIntegrityTamper(t *testing.T) {
	w := fixture(t)
	if _, _, _, err := Load(w.Root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Root, "artifacts/a0001"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Load(w.Root); err == nil {
		t.Fatal("modified evidence accepted")
	}
}

func TestManifestTraversalAndDuplicate(t *testing.T) {
	for _, attack := range []string{"traversal", "duplicate", "symlink"} {
		t.Run(attack, func(t *testing.T) {
			w := fixture(t)
			switch attack {
			case "traversal":
				w.Manifest.Artifacts[0].Path = "artifacts/../../outside"
			case "duplicate":
				w.Manifest.Artifacts = append(w.Manifest.Artifacts, w.Manifest.Artifacts[0])
			case "symlink":
				path := filepath.Join(w.Root, "artifacts/a0001")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", path); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Save(); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := Load(w.Root); err == nil {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
}

func TestImportNoOverwriteAndNoRecursiveOutput(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "auth.log"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Import(root, filepath.Join(root, "out"), "linux"); err == nil {
		t.Fatal("recursive output accepted")
	}
	out := filepath.Join(t.TempDir(), "bundle")
	if err := Import(root, out, "linux"); err != nil {
		t.Fatal(err)
	}
	if err := Import(root, out, "linux"); err == nil {
		t.Fatal("overwrote existing output")
	}
}

func TestEmptySuccessfulArtifact(t *testing.T) {
	w := fixture(t)
	if err := w.Add("empty", "auth", "collected", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Load(w.Root); err != nil {
		t.Fatal(err)
	}
}
