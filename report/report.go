package report

import (
	"encoding/json"
	"fmt"
	"os"

	"api-security-tool/analyzer"
)

func SaveJSON(r analyzer.Report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func SaveHTML(r analyzer.Report, path string) error {
	html := buildHTML(r)
	return os.WriteFile(path, []byte(html), 0644)
}

func buildHTML(r analyzer.Report) string {
	overallColor := riskColor(r.OverallRiskScore)

	cards := ""
	for i, er := range r.EndpointRisks {
		anomalyBadges := ""
		if er.IsTimeAnomaly {
			anomalyBadges += `<span class="badge badge-warn">Time Anomaly</span> `
		}
		if er.IsSizeAnomaly {
			anomalyBadges += `<span class="badge badge-warn">Size Anomaly</span>`
		}

		recs := ""
		for _, rec := range er.Recommendations {
			recs += fmt.Sprintf(`<li>%s</li>`, rec)
		}

		findingCards := ""
		for _, f := range er.Findings {
			sevClass := severityClass(string(f.Severity))
			findingCards += fmt.Sprintf(`
				<div class="finding-card finding-%s">
					<div class="finding-header">
						<span class="badge badge-%s">%s</span>
						<span class="finding-name">%s</span>
					</div>
					<div class="finding-body">
						<div class="finding-row">
							<span class="finding-label">Description</span>
							<span class="finding-val">%s</span>
						</div>
						<div class="finding-row">
							<span class="finding-label">Evidence</span>
							<code class="evidence">%s</code>
						</div>
						<div class="finding-row">
							<span class="finding-label">Tested URL</span>
							<code class="evidence">%s %s</code>
						</div>
					</div>
				</div>`,
				sevClass, sevClass, string(f.Severity),
				f.TestName,
				f.Description,
				f.Evidence,
				f.Method, f.URL,
			)
		}

		if findingCards == "" {
			findingCards = `<p class="no-finding">No active vulnerabilities detected for this endpoint.</p>`
		}

		cards += fmt.Sprintf(`
		<div class="ep-card" id="ep-%d">
			<div class="ep-header" onclick="toggle(%d)">
				<div class="ep-left">
					<span class="method %s">%s</span>
					<code class="ep-url">%s</code>
					%s
				</div>
				<div class="ep-right">
					<div class="score-bar">
						<div class="score-fill" style="width:%.0f%%; background:%s;"></div>
					</div>
					<span class="score-num">%.1f / 100</span>
					<span class="badge badge-%s">%s</span>
					<span class="chevron" id="chev-%d">v</span>
				</div>
			</div>
			<div class="ep-body" id="body-%d">
				<div class="ep-section">
					<div class="section-title">Security Findings (%d)</div>
					%s
				</div>
				<div class="ep-section">
					<div class="section-title">Recommendations</div>
					<ul class="rec-list">%s</ul>
				</div>
			</div>
		</div>`,
			i, i,
			methodClass(er.Method), er.Method,
			er.URL,
			anomalyBadges,
			er.RiskScore, riskColorHex(er.RiskScore),
			er.RiskScore,
			levelClass(er.RiskLevel), string(er.RiskLevel),
			i,
			i,
			len(er.Findings),
			findingCards,
			recs,
		)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>API Security Report</title>
<style>
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; margin: 0; padding: 28px 32px; }
h1 { color: #f8fafc; font-size: 26px; margin-bottom: 4px; }
.meta { color: #64748b; font-size: 13px; margin-bottom: 28px; }
h2 { color: #f1f5f9; font-size: 16px; margin: 32px 0 12px; text-transform: uppercase; letter-spacing: 1px; }
.cards { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 32px; }
.card { background: #1e2433; border-radius: 10px; padding: 18px 24px; min-width: 130px; }
.card-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
.card-value { font-size: 30px; font-weight: 700; margin-top: 4px; }
.c-overall { color: %s; }
.c-critical { color: #ef4444; }
.c-high { color: #f97316; }
.c-medium { color: #eab308; }
.c-low { color: #22c55e; }
.c-anomaly { color: #a78bfa; }
.ep-card { background: #1a2030; border: 1px solid #2d3748; border-radius: 10px; margin-bottom: 10px; overflow: hidden; }
.ep-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; cursor: pointer; user-select: none; }
.ep-header:hover { background: #202838; }
.ep-left { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.ep-right { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
.ep-url { background: #2d3748; padding: 3px 8px; border-radius: 4px; font-size: 13px; color: #cbd5e1; }
.score-bar { background: #2d3748; border-radius: 4px; height: 5px; width: 80px; overflow: hidden; }
.score-fill { height: 100%%; border-radius: 4px; }
.score-num { font-size: 12px; color: #94a3b8; white-space: nowrap; }
.chevron { color: #64748b; font-size: 12px; }
.ep-body { display: none; border-top: 1px solid #2d3748; padding: 20px 18px; }
.ep-body.open { display: block; }
.ep-section { margin-bottom: 20px; }
.section-title { font-size: 13px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }
.finding-card { border-radius: 8px; border: 1px solid; margin-bottom: 10px; overflow: hidden; }
.finding-CRITICAL { border-color: #ef444440; background: #1a0a0a; }
.finding-HIGH { border-color: #f9731640; background: #1a100a; }
.finding-MEDIUM { border-color: #eab30840; background: #1a160a; }
.finding-LOW { border-color: #22c55e40; background: #0a160a; }
.finding-INFO { border-color: #38bdf840; background: #0a1420; }
.finding-header { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-bottom: 1px solid #ffffff08; }
.finding-name { font-size: 13px; font-weight: 600; color: #e2e8f0; }
.finding-body { padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
.finding-row { display: flex; gap: 12px; align-items: baseline; }
.finding-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; min-width: 100px; flex-shrink: 0; }
.finding-val { font-size: 13px; color: #cbd5e1; }
.evidence { background: #0d1117; border: 1px solid #2d3748; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: #7dd3fc; word-break: break-all; }
.no-finding { color: #4b5563; font-size: 13px; font-style: italic; margin: 0; }
.rec-list { margin: 0; padding-left: 18px; }
.rec-list li { font-size: 13px; color: #94a3b8; margin-bottom: 6px; }
.badge { padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-CRITICAL { background: #450a0a; color: #ef4444; border: 1px solid #ef444460; }
.badge-HIGH     { background: #431407; color: #f97316; border: 1px solid #f9731660; }
.badge-MEDIUM   { background: #422006; color: #eab308; border: 1px solid #eab30860; }
.badge-LOW      { background: #052e16; color: #22c55e; border: 1px solid #22c55e60; }
.badge-INFO     { background: #0c1a2e; color: #38bdf8; border: 1px solid #38bdf860; }
.badge-warn     { background: #1c1917; color: #fbbf24; border: 1px solid #fbbf2460; font-size: 11px; padding: 2px 7px; border-radius: 4px; }
.method { padding: 2px 9px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.GET    { background: #1e3a5f; color: #60a5fa; }
.POST   { background: #14532d; color: #4ade80; }
.PUT    { background: #451a03; color: #fb923c; }
.DELETE { background: #450a0a; color: #f87171; }
.PATCH  { background: #2e1065; color: #c084fc; }
</style>
</head>
<body>

<h1>API Security Report</h1>
<div class="meta">Scanned: %s &nbsp;|&nbsp; Endpoints: %d</div>

<div class="cards">
  <div class="card"><div class="card-label">Overall Risk</div><div class="card-value c-overall">%.0f</div></div>
  <div class="card"><div class="card-label">Critical</div><div class="card-value c-critical">%d</div></div>
  <div class="card"><div class="card-label">High</div><div class="card-value c-high">%d</div></div>
  <div class="card"><div class="card-label">Medium</div><div class="card-value c-medium">%d</div></div>
  <div class="card"><div class="card-label">Low</div><div class="card-value c-low">%d</div></div>
  <div class="card"><div class="card-label">Anomalies</div><div class="card-value c-anomaly">%d</div></div>
</div>

<h2>Endpoint Risk Analysis</h2>
%s

<script>
function toggle(i) {
  var body = document.getElementById('body-' + i);
  body.classList.toggle('open');
}
</script>
</body>
</html>`,
		overallColor,
		r.TestedAt.Format("02 Jan 2006 - 15:04:05"),
		r.TotalEndpoints,
		r.OverallRiskScore,
		r.Summary.CriticalFindings,
		r.Summary.HighFindings,
		r.Summary.MediumFindings,
		r.Summary.LowFindings,
		r.Summary.AnomalousEndpoints,
		cards,
	)
}

func riskColor(score float64) string {
	switch {
	case score >= 75:
		return "#ef4444"
	case score >= 50:
		return "#f97316"
	case score >= 25:
		return "#eab308"
	default:
		return "#22c55e"
	}
}

func riskColorHex(score float64) string {
	return riskColor(score)
}

func levelClass(l analyzer.RiskLevel) string {
	return string(l)
}

func methodClass(m string) string {
	return m
}

func severityClass(s string) string {
	return s
}
