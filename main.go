package main

import (
	"fmt"
	"os"
	"sync"

	"api-security-tool/analyzer"
	"api-security-tool/config"
	"api-security-tool/report"
	"api-security-tool/scanner"
	"api-security-tool/tests"

	"github.com/spf13/cobra"
)

func main() {
	var configPath string
	var outputDir string
	var swaggerURL string

	rootCmd := &cobra.Command{
		Use:   "api-security-tool",
		Short: "API güvenlik tarama ve ML risk analiz aracı",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(configPath, outputDir, swaggerURL)
		},
	}

	rootCmd.Flags().StringVarP(&configPath, "config", "c", "config.json", "Konfigürasyon dosyası")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", ".", "Rapor çıktı klasörü")
	rootCmd.Flags().StringVarP(&swaggerURL, "swagger", "s", "", "Swagger/OpenAPI spec URL'i (otomatik keşif)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(configPath, outputDir, swaggerURL string) error {
	var cfg *config.Config
	var err error

	if swaggerURL != "" {
		// Swagger modunda config'i spec'ten oluştur
		fmt.Printf("🔎 Swagger spec okunuyor: %s\n", swaggerURL)
		baseURL, endpoints, fetchErr := scanner.FetchEndpoints(swaggerURL)
		if fetchErr != nil {
			return fetchErr
		}
		cfg = &config.Config{
			BaseURL:     baseURL,
			Endpoints:   endpoints,
			Timeout:     10,
			Concurrency: 5,
		}
	} else {
		// Normal config dosyası modu
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("config yüklenemedi: %w", err)
		}
	}

	fmt.Printf("🔍 %d endpoint taranıyor...\n\n", len(cfg.Endpoints))

	// HTTP client oluştur
	client := scanner.New(cfg.Timeout, cfg.Headers)
	testRunner := tests.New(client)

	// Paralel tarama — goroutine ile
	var mu sync.Mutex
	var results []scanner.Result
	findingsMap := make(map[string][]tests.Finding)

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, ep := range cfg.Endpoints {
		wg.Add(1)
		go func(ep config.Endpoint) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := cfg.BaseURL + ep.URL

			headers := make(map[string]string)
			for k, v := range ep.Headers {
				headers[k] = v
			}
			if cfg.AuthToken != "" {
				headers["Authorization"] = "Bearer " + cfg.AuthToken
			}

			result := client.Do(ep.Method, url, headers, nil)
			findings := testRunner.RunAll(ep.Method, url, headers)
			key := ep.Method + ":" + url

			mu.Lock()
			results = append(results, result)
			findingsMap[key] = findings
			mu.Unlock()

			fmt.Printf("  %-6s %-45s → %d (%d bulgu)\n",
				ep.Method, url, result.StatusCode, len(findings))
		}(ep)
	}

	wg.Wait()
	fmt.Println()

	// ML analizi
	fmt.Println("🤖 ML risk analizi yapılıyor...")
	analysisReport := analyzer.Analyze(results, findingsMap)

	// Raporları kaydet
	jsonPath := outputDir + "/report.json"
	htmlPath := outputDir + "/report.html"

	if err := report.SaveJSON(analysisReport, jsonPath); err != nil {
		return fmt.Errorf("JSON raporu kaydedilemedi: %w", err)
	}
	if err := report.SaveHTML(analysisReport, htmlPath); err != nil {
		return fmt.Errorf("HTML raporu kaydedilemedi: %w", err)
	}

	// Terminal özeti
	fmt.Printf("📊 Genel Risk Skoru: %.1f/100\n", analysisReport.OverallRiskScore)
	fmt.Printf("   Kritik: %d | Yüksek: %d | Orta: %d | Düşük: %d\n",
		analysisReport.Summary.CriticalFindings,
		analysisReport.Summary.HighFindings,
		analysisReport.Summary.MediumFindings,
		analysisReport.Summary.LowFindings,
	)

	if len(analysisReport.TopRisks) > 0 {
		fmt.Println("\n🚨 En Riskli Endpointler:")
		for i, r := range analysisReport.TopRisks {
			fmt.Printf("  %d. [%s] %s %s — %.1f puan\n",
				i+1, r.RiskLevel, r.Method, r.URL, r.RiskScore)
		}
	}

	fmt.Printf("\n✅ Raporlar kaydedildi:\n   %s\n   %s\n", jsonPath, htmlPath)
	return nil
}
