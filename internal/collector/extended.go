//go:build linux || darwin

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"selfdiag.local/rebuild/internal/evidence"
)

type Options struct {
	Profile          string
	Timeout          time.Duration
	SourceRoot       string
	SourceOS         string
	MaxDuration      time.Duration
	MaxProcesses     int
	IncludeBrowser   bool
	IncludeSensitive bool
	IncludeBinaries  bool
}

type gather struct {
	w           *evidence.Writer
	root        *os.Root
	opts        Options
	seen        map[string]bool
	deadline    time.Time
	outRelative string
	live        bool
}

func (g *gather) note(s string) {
	g.w.Manifest.CollectionStatus = "limited"
	if len(g.w.Manifest.CollectionNotes) < 128 {
		g.w.Manifest.CollectionNotes = append(g.w.Manifest.CollectionNotes, s)
	}
}
func (g *gather) check() error {
	if time.Now().After(g.deadline) {
		return fmt.Errorf("collection deadline reached")
	}
	return nil
}
func relative(p string) string { return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(p)), "/") }

func (g *gather) file(path, kind string) error {
	if err := g.check(); err != nil {
		return err
	}
	path = filepath.Clean(path)
	if g.seen[path] {
		return nil
	}
	g.seen[path] = true
	rel := relative(path)
	if g.outRelative != "" && (rel == g.outRelative || strings.HasPrefix(rel, g.outRelative+"/")) {
		g.note("excluded output subtree: " + path)
		return nil
	}
	return g.w.FileAt(g.root, rel, path, kind)
}

func readBounded(root *os.Root, path string, max int64) ([]byte, error) {
	f, err := root.Open(relative(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, fmt.Errorf("selector input exceeds limit")
	}
	return b, err
}

func (g *gather) tree(spec treeSpec) error {
	if err := g.check(); err != nil {
		return err
	}
	// Walk without following directory symlinks. All opens are confined by os.Root.
	count := 0
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		if err := g.check(); err != nil {
			return err
		}
		rel := relative(path)
		if rel == g.outRelative && g.outRelative != "" {
			g.note("excluded output subtree: " + path)
			return nil
		}
		info, err := g.root.Lstat(rel)
		if err != nil {
			return g.file(path, spec.Kind)
		}
		if !info.IsDir() {
			return g.file(path, spec.Kind)
		}
		if depth > spec.MaxDepth {
			g.note("directory depth limit: " + path)
			return nil
		}
		dir, err := g.root.Open(rel)
		if err != nil {
			return g.w.Add(path, spec.Kind, "error", err.Error(), nil)
		}
		defer dir.Close()
		for {
			entries, err := dir.ReadDir(32)
			if err != nil && err != io.EOF {
				return g.w.Add(path, spec.Kind, "error", err.Error(), nil)
			}
			for _, entry := range entries {
				count++
				if count > spec.MaxEntries {
					g.note("directory entry limit: " + spec.Path)
					return nil
				}
				child := filepath.Join(path, entry.Name())
				if entry.IsDir() {
					if e := walk(child, depth+1); e != nil {
						return e
					}
					continue
				}
				if len(spec.Suffixes) > 0 {
					ok := false
					for _, suffix := range spec.Suffixes {
						if strings.HasSuffix(strings.ToLower(entry.Name()), suffix) {
							ok = true
						}
					}
					if !ok {
						continue
					}
				}
				kind := spec.Kind
				if kind == "logs" {
					kind = evidence.Classify(child)
					if kind == "other" {
						kind = "log_file"
					}
					for _, suffix := range []string{".gz", ".xz", ".bz2", ".zst"} {
						if strings.HasSuffix(child, suffix) {
							kind = "compressed_log"
						}
					}
				}
				if e := g.file(child, kind); e != nil {
					return e
				}
			}
			if err == io.EOF {
				return nil
			}
		}
	}
	return walk(spec.Path, 0)
}

func (g *gather) homes() ([]string, error) {
	homes := map[string]bool{}
	if g.opts.SourceOS == "linux" {
		b, err := readBounded(g.root, "/etc/passwd", 512*1024)
		if err != nil {
			g.note("cannot enumerate users: " + err.Error())
		} else {
			for _, line := range strings.Split(string(b), "\n") {
				f := strings.Split(line, ":")
				if len(f) < 7 {
					continue
				}
				uid, err := strconv.Atoi(f[2])
				if err != nil {
					continue
				}
				if uid != 0 && (uid < 1000 || uid >= 65534) {
					continue
				}
				home := filepath.Clean(f[5])
				if filepath.IsAbs(home) && home != "/" && home != "/nonexistent" {
					homes[home] = true
				}
			}
		}
	} else {
		homes["/var/root"] = true
		dir, err := g.root.Open("Users")
		if err != nil {
			g.note("cannot enumerate /Users: " + err.Error())
		} else {
			entries, e := dir.ReadDir(65)
			dir.Close()
			if e != nil && e != io.EOF {
				g.note(e.Error())
			}
			if len(entries) > 64 {
				g.note("user directory enumeration limit")
				entries = entries[:64]
			}
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != "Shared" {
					homes[filepath.Join("/Users", entry.Name())] = true
				}
			}
		}
	}
	if g.live {
		if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) && home != "/" {
			homes[filepath.Clean(home)] = true
		}
	}
	result := []string{}
	for home := range homes {
		result = append(result, home)
	}
	sort.Strings(result)
	if len(result) > 64 {
		g.note("user home limit (64)")
		result = result[:64]
	}
	return result, nil
}

func (g *gather) users() error {
	homes, _ := g.homes()
	for _, home := range homes {
		for _, name := range []string{".bash_history", ".zsh_history", ".history", ".sh_history", ".ksh_history", ".tcsh_history"} {
			if err := g.file(filepath.Join(home, name), "history"); err != nil {
				return err
			}
		}
		for _, name := range []string{".profile", ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".viminfo"} {
			if err := g.file(filepath.Join(home, name), "user_config"); err != nil {
				return err
			}
		}
		for _, path := range []string{filepath.Join(home, ".config/systemd/user"), filepath.Join(home, ".config/autostart")} {
			if g.opts.SourceOS == "linux" {
				if err := g.tree(treeSpec{Path: path, Kind: "persistence", MaxEntries: 32, MaxDepth: 3}); err != nil {
					return err
				}
			}
		}
		if g.opts.SourceOS == "darwin" {
			if err := g.tree(treeSpec{Path: filepath.Join(home, "Library/LaunchAgents"), Kind: "persistence", MaxEntries: 32, MaxDepth: 2}); err != nil {
				return err
			}
		}
		if g.opts.IncludeBrowser {
			if err := g.browser(home); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *gather) browser(home string) error {
	patterns := []string{home + "/.mozilla/firefox/*/places.sqlite*", home + "/.config/google-chrome/*/History*", home + "/.config/chromium/*/History*"}
	if g.opts.SourceOS == "darwin" {
		patterns = []string{home + "/Library/Application Support/Firefox/Profiles/*/places.sqlite*", home + "/Library/Application Support/Google/Chrome/*/History*", home + "/Library/Safari/History.db*"}
	}
	for _, pattern := range patterns {
		matches, err := fs.Glob(g.root.FS(), relative(pattern))
		if err != nil {
			g.note("browser selector failed: " + pattern)
			continue
		}
		if len(matches) == 0 {
			if err := g.w.Add(pattern, "browser_history", "missing", "no matching database files", nil); err != nil {
				return err
			}
		}
		if len(matches) > 32 {
			matches = matches[:32]
			g.note("browser file limit: " + pattern)
		}
		for _, path := range matches {
			if err := g.file("/"+path, "browser_history"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *gather) proc() error {
	dir, err := g.root.Open("proc")
	if err != nil {
		return g.w.Add("/proc", "process_detail", "error", err.Error(), nil)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(4097)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > 4096 {
		g.note("/proc enumeration limit")
		entries = entries[:4096]
	}
	pids := []int{}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e == nil && pid > 0 && entry.IsDir() {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	if len(pids) > g.opts.MaxProcesses {
		g.note("process count limit")
		pids = pids[:g.opts.MaxProcesses]
	}
	for _, pid := range pids {
		base := "/proc/" + strconv.Itoa(pid)
		for _, name := range []string{"status", "stat", "cmdline", "maps", "cgroup", "limits", "stack"} {
			if err := g.file(base+"/"+name, "process_detail"); err != nil {
				return err
			}
		}
		if g.opts.IncludeSensitive {
			if err := g.file(base+"/environ", "process_environment"); err != nil {
				return err
			}
		}
		links := map[string]string{}
		for _, name := range []string{"exe", "cwd", "root"} {
			path := base + "/" + name
			if _, e := g.root.Lstat(relative(path)); e == nil {
				// Readlink captures the target string only, never the target contents.
				target, e := os.Readlink(filepath.Join(g.opts.SourceRoot, relative(path)))
				if e != nil {
					links[name] = "ERROR: " + e.Error()
				} else {
					links[name] = target
				}
			} else {
				links[name] = "ERROR: " + e.Error()
			}
		}
		fd, err := g.root.Open(relative(base + "/fd"))
		if err == nil {
			fds, e := fd.ReadDir(129)
			fd.Close()
			if e != nil && e != io.EOF {
				links["fd_error"] = e.Error()
			}
			if len(fds) > 128 {
				fds = fds[:128]
				g.note("fd limit: " + base)
			}
			for _, entry := range fds {
				path := base + "/fd/" + entry.Name()
				target, e := os.Readlink(filepath.Join(g.opts.SourceRoot, relative(path)))
				if e == nil {
					links["fd/"+entry.Name()] = target
				} else {
					links["fd/"+entry.Name()] = "ERROR: " + e.Error()
				}
			}
		} else {
			links["fd_error"] = err.Error()
		}
		b, _ := json.MarshalIndent(links, "", "  ")
		status := "collected"
		for key, value := range links {
			if key == "fd_error" || strings.HasPrefix(value, "ERROR: ") {
				status = "partial"
			}
		}
		if err := g.w.Add(base+"/{exe,cwd,root,fd}", "process_links", status, "link target strings only; process may change or exit during collection", b); err != nil {
			return err
		}
		if g.opts.IncludeBinaries {
			if target, ok := links["exe"]; ok && filepath.IsAbs(target) && !strings.HasSuffix(target, " (deleted)") {
				if err := g.file(target, "executable"); err != nil {
					return err
				}
			} else {
				if err := g.w.Add(base+"/exe", "executable", "unsupported", "executable path unavailable or deleted; no inode/memory recovery attempted", nil); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func CollectWithOptions(out string, opts Options) error {
	if opts.Profile != "system" && opts.Profile != "triage" && opts.Profile != "extended" {
		return fmt.Errorf("profile must be system, triage, or extended")
	}
	if opts.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if opts.Profile != "extended" && (opts.IncludeBrowser || opts.IncludeSensitive || opts.IncludeBinaries) {
		return fmt.Errorf("optional evidence flags require extended profile")
	}
	if opts.SourceRoot == "" {
		opts.SourceRoot = "/"
	}
	rootPath, err := filepath.Abs(opts.SourceRoot)
	if err != nil {
		return err
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return err
	}
	opts.SourceRoot = rootPath
	live := rootPath == "/"
	if opts.SourceOS == "" {
		opts.SourceOS = runtime.GOOS
	}
	if opts.SourceOS != "linux" && opts.SourceOS != "darwin" {
		return fmt.Errorf("source OS must be linux or darwin")
	}
	if live && opts.SourceOS != runtime.GOOS {
		return fmt.Errorf("live source OS must match runtime")
	}
	if opts.MaxDuration == 0 {
		opts.MaxDuration = 3 * time.Minute
	}
	if opts.MaxDuration < 0 {
		return fmt.Errorf("deadline must be positive")
	}
	if opts.MaxProcesses == 0 {
		opts.MaxProcesses = 32
	}
	if opts.MaxProcesses < 1 || opts.MaxProcesses > 128 {
		return fmt.Errorf("max-processes must be 1..128")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	arch := runtime.GOARCH
	mode := "collect:" + opts.Profile
	if !live {
		arch = "unknown"
		mode = "filesystem:" + opts.Profile
	}
	w, err := evidence.New(out, opts.SourceOS, arch, mode)
	if err != nil {
		return err
	}
	w.Manifest.CollectionStatus = "completed"
	outAbs, _ := filepath.Abs(out)
	outAbs, _ = filepath.EvalSymlinks(outAbs)
	rel, _ := filepath.Rel(rootPath, outAbs)
	excluded := ""
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		excluded = filepath.ToSlash(rel)
	}
	g := gather{w: w, root: root, opts: opts, live: live, seen: map[string]bool{}, deadline: time.Now().Add(opts.MaxDuration), outRelative: excluded}
	run := func() error {
		files, commands, trees := specsForOS(opts.SourceOS, opts.Profile)
		for _, s := range files {
			if err := g.file(s.path, s.kind); err != nil {
				return err
			}
		}
		for _, s := range commands {
			if err := g.check(); err != nil {
				return err
			}
			if !live {
				if err := w.Add(fmt.Sprint(s.args), s.kind, "unsupported", "commands disabled for filesystem root", nil); err != nil {
					return err
				}
				continue
			}
			d := opts.Timeout
			if remaining := time.Until(g.deadline); remaining < d {
				d = remaining
			}
			ctx, cancel := context.WithTimeout(context.Background(), d)
			data, status, detail := command(ctx, s.args)
			cancel()
			if err := w.Add(fmt.Sprint(s.args), s.kind, status, detail, data); err != nil {
				return err
			}
		}
		if opts.Profile == "extended" {
			// Persistence and per-process artifacts precede bulk log/config trees.
			for _, tree := range trees {
				if tree.Kind == "persistence" {
					if err := g.tree(tree); err != nil {
						return err
					}
				}
			}
			if err := g.users(); err != nil {
				return err
			}
			if opts.SourceOS == "linux" {
				if opts.IncludeSensitive {
					if err := g.file("/etc/shadow", "account_secrets"); err != nil {
						return err
					}
				}
				if err := g.proc(); err != nil {
					return err
				}
			}
			for _, tree := range trees {
				if tree.Kind != "persistence" {
					if err := g.tree(tree); err != nil {
						return err
					}
				}
			}
		} else if opts.Profile == "triage" {
			if live {
				home, e := os.UserHomeDir()
				if e != nil {
					g.note("home unavailable: " + e.Error())
				} else {
					for _, name := range []string{".bash_history", ".zsh_history"} {
						if err := g.file(filepath.Join(home, name), "history"); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	err = run()
	if err != nil {
		w.Manifest.CollectionStatus = "failed"
		if errors.Is(err, evidence.ErrBudget) || strings.Contains(err.Error(), "deadline") {
			w.Manifest.CollectionStatus = "limited"
		}
		w.Manifest.CollectionNotes = append(w.Manifest.CollectionNotes, err.Error())
	}
	saveErr := w.Save()
	return errors.Join(err, saveErr)
}
