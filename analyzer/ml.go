package analyzer

import (
	"math"
	"time"

	"api-security-tool/scanner"
	"api-security-tool/tests"
)

// EndpointMetrics — bir endpoint'in ölçüm verileri
type EndpointMetrics struct {
	URL          string
	Method       string
	ResponseTime time.Duration
	ResponseSize int64
	StatusCode   int
	Findings     []tests.Finding
}

// RiskLevel — hesaplanan risk seviyesi
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

// EndpointRisk — bir endpoint için ML tabanlı risk analizi sonucu
type EndpointRisk struct {
	URL             string
	Method          string
	RiskScore       float64 // 0-100 arası
	RiskLevel       RiskLevel
	AnomalyScore    float64 // Z-score tabanlı anomali puanı
	IsTimeAnomaly   bool    // Yanıt süresi anomali mi?
	IsSizeAnomaly   bool    // Yanıt boyutu anomali mi?
	FindingCount    int
	CriticalCount   int
	HighCount       int
	Findings        []tests.Finding
	Recommendations []string
}

// Report — tüm analiz sonucu
type Report struct {
	TotalEndpoints   int
	TestedAt         time.Time
	EndpointRisks    []EndpointRisk
	OverallRiskScore float64
	TopRisks         []EndpointRisk
	Summary          Summary
}

// Summary — genel istatistikler
type Summary struct {
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
	AnomalousEndpoints int
}

// Analyze — tüm endpoint sonuçlarını ML ile analiz eder
func Analyze(results []scanner.Result, findingsMap map[string][]tests.Finding) Report {
	metrics := buildMetrics(results, findingsMap)

	// İstatistiksel değerleri hesapla
	responseTimes := extractResponseTimes(metrics)
	responseSizes := extractResponseSizes(metrics)

	meanTime, stdTime := meanAndStd(responseTimes)
	meanSize, stdStd := meanAndStd(responseSizes)

	var risks []EndpointRisk
	summary := Summary{}

	for _, m := range metrics {
		risk := computeRisk(m, meanTime, stdTime, meanSize, stdStd)
		risks = append(risks, risk)

		// Summary güncelle
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

// buildMetrics — scanner result ve findings'i birleştirir
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

// computeRisk — tek endpoint için risk skoru hesaplar
func computeRisk(m EndpointMetrics, meanTime, stdTime, meanSize, stdSize float64) EndpointRisk {
	risk := EndpointRisk{
		URL:    m.URL,
		Method: m.Method,
	}

	// 1. Finding tabanlı skor (0-60 puan)
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

	// 2. Anomali skoru — Z-score tabanlı (0-25 puan)
	timeZScore := 0.0
	if stdTime > 0 {
		timeZScore = math.Abs(float64(m.ResponseTime.Milliseconds())-meanTime) / stdTime
	}

	sizeZScore := 0.0
	if stdSize > 0 {
		sizeZScore = math.Abs(float64(m.ResponseSize)-meanSize) / stdSize
	}

	// Z-score > 2 ise anomali
	risk.IsTimeAnomaly = timeZScore > 2.0
	risk.IsSizeAnomaly = sizeZScore > 2.0
	risk.AnomalyScore = math.Max(timeZScore, sizeZScore)

	anomalyScore := math.Min((timeZScore+sizeZScore)*5, 25)

	// 3. HTTP status kodu riski (0-15 puan)
	statusScore := 0.0
	switch {
	case m.StatusCode == 500:
		statusScore = 15 // Sunucu hatası — injection ipucu olabilir
	case m.StatusCode == 403:
		statusScore = 0 // İyi — erişim engelli
	case m.StatusCode == 200 && m.Method == "DELETE":
		statusScore = 10 // Silme işlemi başarılı olmamalıydı?
	}

	risk.RiskScore = math.Min(findingScore+anomalyScore+statusScore, 100)
	risk.RiskLevel = scoreToLevel(risk.RiskScore)
	risk.Recommendations = buildRecommendations(risk)

	return risk
}

// scoreToLevel — sayısal skoru seviyeye çevirir
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

// buildRecommendations — risk bulgularına göre öneri üretir
func buildRecommendations(r EndpointRisk) []string {
	var recs []string

	if r.CriticalCount > 0 {
		recs = append(recs, "Kritik açıklar acilen giderilmeli — bu endpoint'i geçici olarak devre dışı bırakın.")
	}
	if r.HighCount > 0 {
		recs = append(recs, "Yüksek riskli bulgular bir sonraki sprint'te düzeltilmeli.")
	}
	if r.IsTimeAnomaly {
		recs = append(recs, "Yanıt süresi anormal — SQL injection veya yavaş sorgu olabilir, query loglarını inceleyin.")
	}
	if r.IsSizeAnomaly {
		recs = append(recs, "Yanıt boyutu anormal — veri sızıntısı kontrolü yapın.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Belirgin bir risk tespit edilmedi, periyodik taramayı sürdürün.")
	}

	return recs
}

// computeOverallScore — tüm endpoint'lerin ağırlıklı ortalaması
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

// getTopRisks — en yüksek riskli N endpoint'i döner
func getTopRisks(risks []EndpointRisk, n int) []EndpointRisk {
	// Basit bubble sort — N küçük olduğu için yeterli
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

// meanAndStd — ortalama ve standart sapma hesaplar
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
