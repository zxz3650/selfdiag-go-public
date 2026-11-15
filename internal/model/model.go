package model

import "time"

const Schema = 1

type Artifact struct {
	ID                string     `json:"id"`
	Source            string     `json:"source"`
	Path              string     `json:"path,omitempty"`
	Kind              string     `json:"kind"`
	Status            string     `json:"status"`
	SHA256            string     `json:"sha256,omitempty"`
	Bytes             int64      `json:"bytes"`
	Detail            string     `json:"detail,omitempty"`
	CapturedUTC       time.Time  `json:"captured_utc"`
	SourceSize        *int64     `json:"source_size,omitempty"`
	SourceMode        string     `json:"source_mode,omitempty"`
	SourceModifiedUTC *time.Time `json:"source_modified_utc,omitempty"`
}

type Manifest struct {
	Schema           int        `json:"schema_version"`
	SourceOS         string     `json:"source_os"`
	SourceArch       string     `json:"source_arch"`
	CollectorOS      string     `json:"collector_os"`
	CollectorArch    string     `json:"collector_arch"`
	Started          time.Time  `json:"started_utc"`
	Mode             string     `json:"mode"`
	Artifacts        []Artifact `json:"artifacts"`
	CollectionStatus string     `json:"collection_status,omitempty"`
	CollectionNotes  []string   `json:"collection_notes,omitempty"`
}

type Evidence struct {
	ArtifactID string `json:"artifact_id"`
	Source     string `json:"source"`
	Line       int    `json:"line"`
	Text       string `json:"text"`
}

type RuleResult struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	Score     int        `json:"score"`
	Execution string     `json:"execution_status"`
	Verdict   string     `json:"verdict"`
	Coverage  string     `json:"coverage"`
	Reason    string     `json:"reason,omitempty"`
	Evidence  []Evidence `json:"evidence"`
}

type Report struct {
	Schema         int            `json:"schema_version"`
	Version        string         `json:"version"`
	SourceOS       string         `json:"source_os"`
	AnalyzerOS     string         `json:"analyzer_os"`
	Analyzed       time.Time      `json:"analyzed_utc"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	Counts         map[string]int `json:"counts"`
	Artifacts      []Artifact     `json:"artifacts"`
	Rules          []RuleResult   `json:"rules"`
	Limitations    []string       `json:"limitations"`
}
