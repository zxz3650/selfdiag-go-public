package detector

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"selfdiag.local/rebuild/internal/evidence"
	"selfdiag.local/rebuild/internal/model"
)

const Version = "0.2.0"
const LoginID = "bruteforce_Failed_password_for_root"
const PersistenceID = "detect_persistence_registration_log"
const PortscanID = "detect_portscan_tool_execution"

//go:embed catalog.json
var catalogJSON []byte

type Rule struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Score       int    `json:"score"`
	File        string `json:"file"`
	TargetOS    string `json:"target_os"`
	Backend     string `json:"backend"`
	Implemented bool   `json:"implemented"`
}

func Catalog() []Rule {
	var r []Rule
	if err := json.Unmarshal(catalogJSON, &r); err != nil {
		panic(err)
	}
	for i := range r {
		r[i].Implemented = supported(r[i].ID)
	}
	return r
}

var persistence = []*regexp.Regexp{
	regexp.MustCompile(`COMMAND=.*(systemctl +(enable|link)|update-rc\.d|chkconfig|crontab)`),
	regexp.MustCompile(`systemd: +(Created symlink|Enabled unit files)`),
	regexp.MustCompile(`(crond|cron)\[[0-9]+\]: .*RELOAD`),
	regexp.MustCompile(`^ *(systemctl +(enable|link)|update-rc\.d|chkconfig|crontab) `),
	regexp.MustCompile(`(>> +(\~\/\.|\/etc\/)(\.bashrc|\.profile|\.zshrc|rc\.local))|chmod +\+x +\/etc\/rc\.local`),
}
var portscan = []*regexp.Regexp{regexp.MustCompile(`COMMAND=.*(nmap|masscan|zenmap)`), regexp.MustCompile(`^ *(nmap|masscan|zenmap) `)}

func supported(id string) bool { return id == LoginID || id == PersistenceID || id == PortscanID }
func relevant(id, kind string) bool {
	if id == LoginID {
		return kind == "auth"
	}
	return kind == "auth" || kind == "history" || kind == "event_log"
}

func reference(a model.Artifact, n int, line string) model.Evidence {
	r := []rune(line)
	if len(r) > 1000 {
		line = string(r[:1000]) + "… [excerpt limited]"
	}
	return model.Evidence{ArtifactID: a.ID, Source: a.Source, Line: n, Text: line}
}

type loginEvent struct {
	at  time.Time
	ref model.Evidence
}

func parseTime(line string, year int) (time.Time, error) {
	if f := strings.Fields(line); len(f) > 0 {
		if t, e := time.Parse(time.RFC3339Nano, f[0]); e == nil {
			return t, nil
		}
	}
	if len(line) >= 15 {
		return time.ParseInLocation("Jan _2 15:04:05 2006", line[:15]+" "+strconv.Itoa(year), time.UTC)
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp")
}

// Explicit MVP semantics: >=15 root failures within an inclusive 60-second
// window, per file, sorted by parsed timestamp; no grouping by source IP.
// Exact equivalence with the vendor's CountInSecond is not asserted.
func loginMatches(a model.Artifact, lines []string, year int) ([]model.Evidence, bool) {
	events := []loginEvent{}
	complete := true
	for i, line := range lines {
		if !strings.Contains(line, "Failed password for root from") {
			continue
		}
		t, err := parseTime(line, year)
		if err != nil {
			complete = false
			continue
		}
		events = append(events, loginEvent{at: t, ref: reference(a, i+1, line)})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].at.Before(events[j].at) })
	left := 0
	for right := range events {
		for events[right].at.Sub(events[left].at) > 60*time.Second {
			left++
		}
		if right-left+1 >= 15 {
			refs := []model.Evidence{}
			for _, event := range events[left : right+1] {
				refs = append(refs, event.ref)
			}
			return refs, complete
		}
	}
	return nil, complete
}

func Analyze(root string) (model.Report, error) {
	m, data, hash, err := evidence.Load(root)
	if err != nil {
		return model.Report{}, err
	}
	r := model.Report{Schema: model.Schema, Version: Version, SourceOS: m.SourceOS, AnalyzerOS: runtime.GOOS,
		Analyzed: time.Now().UTC(), ManifestSHA256: hash, Artifacts: m.Artifacts, Counts: map[string]int{}, Rules: []model.RuleResult{},
		Limitations: []string{
			"Only three Linux log detectors are implemented; remaining catalog rules are unsupported.",
			"No native macOS detection rules yet; Linux rules are not applied to macOS evidence.",
			"Coverage describes supplied artifacts, not the entire source system; a match is not proof of compromise.",
			"Syslog timestamps without a year/zone assume the bundle start year and UTC; the original line is preserved.",
			"Login rule: >=15 failures per file in an inclusive 60-second window; exact vendor boundary semantics remain unverified.",
			"SHA-256 detects changes against the manifest; the manifest is not externally signed.",
			"At most 100 evidence excerpts per rule are reported; full input artifacts remain available.",
		}}
	if m.CollectionStatus != "" {
		r.Limitations = append(r.Limitations, "Collection status: "+m.CollectionStatus)
	}
	for _, note := range m.CollectionNotes {
		r.Limitations = append(r.Limitations, "Collection note: "+note)
	}
	for _, rule := range Catalog() {
		result := model.RuleResult{ID: rule.ID, Title: rule.Title, Score: rule.Score, Execution: "unsupported", Verdict: "unknown", Coverage: "none", Evidence: []model.Evidence{}, Reason: "detector not implemented"}
		if rule.TargetOS != m.SourceOS {
			result.Execution = "skipped"
			result.Reason = "not applicable to source OS"
		} else if supported(rule.ID) {
			readable := 0
			complete := m.CollectionStatus != "limited" && m.CollectionStatus != "failed"
			for _, a := range m.Artifacts {
				if !relevant(rule.ID, a.Kind) {
					continue
				}
				b, ok := data[a.ID]
				if !ok {
					complete = false
					continue
				}
				readable++
				if a.Status != "collected" {
					complete = false
				}
				if !utf8.Valid(b) {
					complete = false
				}
				lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
				var refs []model.Evidence
				if rule.ID == LoginID {
					var ok bool
					refs, ok = loginMatches(a, lines, m.Started.Year())
					complete = complete && ok
				} else {
					patterns := persistence
					if rule.ID == PortscanID {
						patterns = portscan
					}
					for i, line := range lines {
						for _, pattern := range patterns {
							if pattern.MatchString(line) {
								refs = append(refs, reference(a, i+1, line))
								break
							}
						}
						if len(refs) >= 100 {
							break
						}
					}
				}
				for _, ref := range refs {
					if len(result.Evidence) < 100 {
						result.Evidence = append(result.Evidence, ref)
					}
				}
			}
			result.Reason = ""
			if readable == 0 {
				result.Execution = "skipped"
				result.Reason = "required readable evidence is missing"
			} else {
				result.Execution = "evaluated"
				result.Coverage = "complete"
				result.Verdict = "not_matched"
				if !complete {
					result.Coverage = "partial"
					result.Verdict = "unknown"
					result.Reason = "input missing, incomplete, invalid UTF-8, or login timestamp unparsed"
				}
				if len(result.Evidence) > 0 {
					result.Verdict = "matched"
				}
			}
		}
		r.Counts[result.Execution]++
		r.Counts[result.Verdict]++
		r.Rules = append(r.Rules, result)
	}
	return r, nil
}
