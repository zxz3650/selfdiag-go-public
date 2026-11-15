//go:build linux || darwin

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"selfdiag.local/rebuild/internal/collector"
	"selfdiag.local/rebuild/internal/detector"
	"selfdiag.local/rebuild/internal/evidence"
	"selfdiag.local/rebuild/internal/report"
)

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: selfdiag version|rules|plan|collect|import|verify|analyze")
	}
	if args[0] == "version" {
		fmt.Printf("selfdiag %s %s/%s\n", detector.Version, runtime.GOOS, runtime.GOARCH)
		return nil
	}
	if args[0] == "rules" {
		return json.NewEncoder(os.Stdout).Encode(detector.Catalog())
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	out := f.String("out", "", "new output directory")
	input := f.String("input", "", "evidence bundle directory")
	root := f.String("root", "", "source directory; collect with non-root directory disables live commands")
	sourceOS := f.String("source-os", "linux", "source OS: linux or darwin (import only)")
	profile := f.String("profile", "system", "collection profile: system, triage, or extended")
	timeout := f.Duration("timeout", 10*time.Second, "per-command timeout")
	deadline := f.Duration("deadline", 3*time.Minute, "cooperative overall collection deadline")
	maxProcesses := f.Int("max-processes", 32, "maximum Linux process details (1..128)")
	browser := f.Bool("include-browser", false, "extended: collect browser history databases and journals")
	sensitive := f.Bool("include-sensitive", false, "extended: include Linux shadow and process environments")
	binaries := f.Bool("include-binaries", false, "extended: copy reachable Linux process executable files")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	switch args[0] {
	case "plan":
		p, err := collector.Plan(*sourceOS, *profile)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(p)
	case "collect":
		if *out == "" {
			return fmt.Errorf("--out required")
		}
		target := *sourceOS
		if *root == "" {
			target = runtime.GOOS
			f.Visit(func(flag *flag.Flag) {
				if flag.Name == "source-os" {
					target = *sourceOS
				}
			})
		}
		return collector.CollectWithOptions(*out, collector.Options{Profile: *profile, Timeout: *timeout, SourceRoot: *root, SourceOS: target, MaxDuration: *deadline, MaxProcesses: *maxProcesses, IncludeBrowser: *browser, IncludeSensitive: *sensitive, IncludeBinaries: *binaries})
	case "import":
		if *out == "" || *root == "" {
			return fmt.Errorf("--root and --out required")
		}
		return evidence.Import(*root, *out, *sourceOS)
	case "verify":
		if *input == "" {
			return fmt.Errorf("--input required")
		}
		m, _, hash, err := evidence.Load(*input)
		if err != nil {
			return err
		}
		fmt.Printf("verified %d artifacts; manifest SHA256 %s\n", len(m.Artifacts), hash)
		return nil
	case "analyze":
		if *input == "" || *out == "" {
			return fmt.Errorf("--input and --out required")
		}
		r, err := detector.Analyze(*input)
		if err != nil {
			return err
		}
		if err := report.Write(*out, r); err != nil {
			return err
		}
		fmt.Printf("matched=%d not_matched=%d unknown=%d unsupported=%d skipped=%d report=%s/report.html\n", r.Counts["matched"], r.Counts["not_matched"], r.Counts["unknown"], r.Counts["unsupported"], r.Counts["skipped"], *out)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
