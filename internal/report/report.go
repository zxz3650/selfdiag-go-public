package report

import (
	"html/template"
	"os"
	"path/filepath"

	"selfdiag.local/rebuild/internal/evidence"
	"selfdiag.local/rebuild/internal/model"
)

const page = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>selfdiag Go 결과</title><style>body{font:15px/1.6 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#17212b}table{border-collapse:collapse;width:100%}th,td{padding:10px;border:1px solid #ccd4dc;text-align:left;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:12px}small{color:#526170}</style></head><body>
<h1>selfdiag Go 분석 결과</h1><p>버전 {{.Version}} · 증거 OS: {{.SourceOS}} · 분석 OS: {{.AnalyzerOS}} · {{.Analyzed}}</p>
<p>탐지 {{index .Counts "matched"}} · 미탐지 {{index .Counts "not_matched"}} · 판단 불가 {{index .Counts "unknown"}} · 미지원 {{index .Counts "unsupported"}} · 건너뜀 {{index .Counts "skipped"}}</p>
<p>전체 시스템의 안전 판정이 아닙니다. 미지원·미검사·부분 수집을 정상으로 집계하지 않습니다.</p>
<h2>범위와 제한</h2><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
<h2>룰 결과</h2><table><tr><th>룰</th><th>실행 / 판정 / 범위</th><th>점수와 근거</th></tr>{{range .Rules}}<tr><td>{{.Title}}<br><small>{{.ID}}</small></td><td>{{.Execution}} / {{.Verdict}} / {{.Coverage}}<br>{{.Reason}}</td><td>점수 {{.Score}}{{range .Evidence}}<p>{{.Source}}:{{.Line}} ({{.ArtifactID}})</p><pre>{{.Text}}</pre>{{end}}</td></tr>{{end}}</table>
<h2>수집 자료</h2><table><tr><th>자료</th><th>상태</th><th>바이트 / SHA-256</th></tr>{{range .Artifacts}}<tr><td>{{.Source}}</td><td>{{.Status}}<br>{{.Detail}}</td><td>{{.Bytes}}<br><small>{{.SHA256}}</small></td></tr>{{end}}</table><p>Manifest SHA-256: {{.ManifestSHA256}}</p></body></html>`

func Write(out string, r model.Report) error {
	if err := evidence.NewDir(out); err != nil {
		return err
	}
	if err := evidence.WriteJSON(filepath.Join(out, "report.json"), r); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(out, "report.html"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = template.Must(template.New("report").Parse(page)).Execute(f, r)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
