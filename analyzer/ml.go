package analyzer

import (
	"math"
	"time"

	"api-security-tool/scanner"
	"api-security-tool/tests"
)

type EndpointMetrics struct {
	URL          string
	Method       string
	ResponseTime time.Duration
	ResponseSize int64
	StatusCode   int
	Findings     []tests.Finding
}

type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

type EndpointRisk struct {
	URL             string
	Method          string
	RiskScore       float64
	RiskLevel       RiskLevel
	AnomalyScore    float64
	IsTimeAnomaly   bool
	IsSizeAnomaly   bool
	FindingCount    int
	CriticalCount   int
	HighCount       int
	Findings        []tests.Finding
	Recommendations []string
}

type Report struct {
	TotalEndpoints   int
	TestedAt         time.Time
	EndpointRisks    []EndpointRisk
	OverallRiskScore float64
	TopRisks         []EndpointRisk
	Summary          Summary
}

type Summary struct {
	CriticalFindings   int
	HighFindings       int
	MediumFindings     int
	LowFindings        int
	AnomalousEndpoints int
}

func Analyze(results []scanner.Result, findingsMap map[string][]tests.Finding) Report {
	metrics := buildMetrics(results, findingsMap)

	responseTimes := extractResponseTimes(metrics)
	responseSizes := extractResponseSizes(metrics)

	meanTime, stdTime := meanAndStd(responseTimes)
	meanSize, stdStd := meanAndStd(responseSizes)

	var risks []EndpointRisk
	summary := Summary{}

	for _, m := range metrics {
		risk := computeRisk(m, meanTime, stdTime, meanSize, stdStd)
		risks = append(risks, risk)

		for _, f := range m.Findings {
			switch f.Severity {
			case tests.Critical:
				summary.CriticalFindings++
			case tests.High:
				summary.HighFindings++
			case tests.Medium:
				summary.MediumFindings++
			case tests.Low:
				summary.LowFindings++
			}
		}
		if risk.IsTimeAnomaly || risk.IsSizeAnomaly {
			summary.AnomalousEndpoints++
		}
	}

	overallScore := computeOverallScore(risks)
	topRisks := getTopRisks(risks, 5)

	return Report{
		TotalEndpoints:   len(metrics),
		TestedAt:         time.Now(),
		EndpointRisks:    risks,
		OverallRiskScore: overallScore,
		TopRisks:         topRisks,
		Summary:          summary,
	}
}

func buildMetrics(results []scanner.Result, findingsMap map[string][]tests.Finding) []EndpointMetrics {
	var metrics []EndpointMetrics
	for _, r := range results {
		key := r.Method + ":" + r.URL
		metrics = append(metrics, EndpointMetrics{
			URL:          r.URL,
			Method:       r.Method,
			ResponseTime: r.ResponseTime,
			ResponseSize: r.ResponseSize,
			StatusCode:   r.StatusCode,
			Findings:     findingsMap[key],
		})
	}
	return metrics
}

func computeRisk(m EndpointMetrics, meanTime, stdTime, meanSize, stdSize float64) EndpointRisk {
	risk := EndpointRisk{
		URL:    m.URL,
		Method: m.Method,
	}

	findingScore := 0.0
	for _, f := range m.Findings {
		switch f.Severity {
		case tests.Critical:
			findingScore += 20
			risk.CriticalCount++
		case tests.High:
			findingScore += 12
			risk.HighCount++
		case tests.Medium:
			findingScore += 6
		case tests.Low:
			findingScore += 2
		}
	}
	risk.FindingCount = len(m.Findings)
	risk.Findings = m.Findings
	findingScore = math.Min(findingScore, 60)

	timeZScore := 0.0
	if stdTime > 0 {
		timeZScore = math.Abs(float64(m.ResponseTime.Milliseconds())-meanTime) / stdTime
	}

	sizeZScore := 0.0
	if stdSize > 0 {
		sizeZScore = math.Abs(float64(m.ResponseSize)-meanSize) / stdSize
	}

	risk.IsTimeAnomaly = timeZScore > 2.0
	risk.IsSizeAnomaly = sizeZScore > 2.0
	risk.AnomalyScore = math.Max(timeZScore, sizeZScore)

	anomalyScore := math.Min((timeZScore+sizeZScore)*5, 25)

	statusScore := 0.0
	switch {
	case m.StatusCode == 500:
		statusScore = 15
	case m.StatusCode == 403:
		statusScore = 0
	case m.StatusCode == 200 && m.Method == "DELETE":
		statusScore = 10
	}

	risk.RiskScore = math.Min(findingScore+anomalyScore+statusScore, 100)
	risk.RiskLevel = scoreToLevel(risk.RiskScore)
	risk.Recommendations = buildRecommendations(risk)

	return risk
}

func scoreToLevel(score float64) RiskLevel {
	switch {
	case score >= 75:
		return RiskCritical
	case score >= 50:
		return RiskHigh
	case score >= 25:
		return RiskMedium
	default:
		return RiskLow
	}
}

func buildRecommendations(r EndpointRisk) []string {
	var recs []string

	if r.CriticalCount > 0 {
		recs = append(recs, "Critical vulnerabilities must be addressed immediately.")
	}
	if r.HighCount > 0 {
		recs = append(recs, "High severity findings should be fixed in the next sprint.")
	}
	if r.IsTimeAnomaly {
		recs = append(recs, "Response time anomaly detected — possible SQL injection or slow query.")
	}
	if r.IsSizeAnomaly {
		recs = append(recs, "Response size anomaly detected — check for data leakage.")
	}
	if len(recs) == 0 {
		recs = append(recs, "No significant risks detected. Continue periodic scanning.")
	}

	return recs
}

func computeOverallScore(risks []EndpointRisk) float64 {
	if len(risks) == 0 {
		return 0
	}
	total := 0.0
	for _, r := range risks {
		total += r.RiskScore
	}
	return total / float64(len(risks))
}

func getTopRisks(risks []EndpointRisk, n int) []EndpointRisk {
	sorted := make([]EndpointRisk, len(risks))
	copy(sorted, risks)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].RiskScore > sorted[i].RiskScore {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}

func meanAndStd(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))

	return mean, math.Sqrt(variance)
}

func extractResponseTimes(metrics []EndpointMetrics) []float64 {
	vals := make([]float64, len(metrics))
	for i, m := range metrics {
		vals[i] = float64(m.ResponseTime.Milliseconds())
	}
	return vals
}

func extractResponseSizes(metrics []EndpointMetrics) []float64 {
	vals := make([]float64, len(metrics))
	for i, m := range metrics {
		vals[i] = float64(m.ResponseSize)
	}
	return vals
}
