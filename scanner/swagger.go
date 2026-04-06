package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"api-security-tool/config"
)

// OpenAPI3 — Swagger/OpenAPI 3.0 spec yapısı
type OpenAPI3 struct {
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths map[string]map[string]struct {
		Summary     string `json:"summary"`
		OperationID string `json:"operationId"`
	} `json:"paths"`
}

// SwaggerV2 — Swagger 2.0 spec yapısı
type SwaggerV2 struct {
	Host     string `json:"host"`
	BasePath string `json:"basePath"`
	Schemes  []string `json:"schemes"`
	Paths    map[string]map[string]struct {
		Summary     string `json:"summary"`
		OperationID string `json:"operationId"`
	} `json:"paths"`
}

// FetchEndpoints — Swagger URL'inden tüm endpoint'leri çeker
func FetchEndpoints(swaggerURL string) (string, []config.Endpoint, error) {
	resp, err := http.Get(swaggerURL)
	if err != nil {
		return "", nil, fmt.Errorf("swagger URL'e erişilemedi: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	// Spec URL'inden host'u çıkar (relative server URL'ler için fallback)
	parsedURL, _ := url.Parse(swaggerURL)
	specHost := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// OpenAPI 3 mi Swagger 2 mi?
	if strings.Contains(string(data), `"openapi"`) {
		return parseOpenAPI3(data, specHost)
	}
	return parseSwaggerV2(data, specHost)
}

// resolveBaseURL — relative server URL'i absolute'a çevirir
func resolveBaseURL(serverURL, specHost string) string {
	if strings.HasPrefix(serverURL, "http://") || strings.HasPrefix(serverURL, "https://") {
		return serverURL
	}
	// Relative URL — spec'in host'uyla birleştir
	return specHost + serverURL
}

// replacePathParams — {petId} gibi path parametrelerini örnek değerlerle değiştirir
var pathParamRe = regexp.MustCompile(`\{[^}]+\}`)

func replacePathParams(path string) string {
	return pathParamRe.ReplaceAllStringFunc(path, func(param string) string {
		name := strings.ToLower(param[1 : len(param)-1])
		switch {
		case strings.Contains(name, "id") || strings.Contains(name, "order"):
			return "1"
		case strings.Contains(name, "username") || strings.Contains(name, "user"):
			return "testuser"
		case strings.Contains(name, "name"):
			return "test"
		case strings.Contains(name, "tag"):
			return "available"
		default:
			return "1"
		}
	})
}

func parseOpenAPI3(data []byte, specHost string) (string, []config.Endpoint, error) {
	var spec OpenAPI3
	if err := json.Unmarshal(data, &spec); err != nil {
		return "", nil, fmt.Errorf("OpenAPI3 parse hatası: %w", err)
	}

	baseURL := specHost
	if len(spec.Servers) > 0 {
		baseURL = resolveBaseURL(spec.Servers[0].URL, specHost)
	}

	endpoints := extractEndpoints(spec.Paths)
	fmt.Printf("📋 OpenAPI 3.0 spec bulundu — %d endpoint keşfedildi\n", len(endpoints))
	return baseURL, endpoints, nil
}

func parseSwaggerV2(data []byte, specHost string) (string, []config.Endpoint, error) {
	var spec SwaggerV2
	if err := json.Unmarshal(data, &spec); err != nil {
		return "", nil, fmt.Errorf("Swagger 2.0 parse hatası: %w", err)
	}

	scheme := "https"
	if len(spec.Schemes) > 0 {
		scheme = spec.Schemes[0]
	}
	host := spec.Host
	if host == "" {
		u, _ := url.Parse(specHost)
		host = u.Host
	}
	baseURL := fmt.Sprintf("%s://%s%s", scheme, host, spec.BasePath)

	// Paths map'i OpenAPI3 formatına dönüştür
	paths := make(map[string]map[string]struct {
		Summary     string `json:"summary"`
		OperationID string `json:"operationId"`
	})
	for path, methods := range spec.Paths {
		paths[path] = make(map[string]struct {
			Summary     string `json:"summary"`
			OperationID string `json:"operationId"`
		})
		for method, op := range methods {
			paths[path][method] = struct {
				Summary     string `json:"summary"`
				OperationID string `json:"operationId"`
			}{Summary: op.Summary, OperationID: op.OperationID}
		}
	}

	endpoints := extractEndpoints(paths)
	fmt.Printf("📋 Swagger 2.0 spec bulundu — %d endpoint keşfedildi\n", len(endpoints))
	return baseURL, endpoints, nil
}

func extractEndpoints(paths map[string]map[string]struct {
	Summary     string `json:"summary"`
	OperationID string `json:"operationId"`
}) []config.Endpoint {
	var endpoints []config.Endpoint
	for path, methods := range paths {
		resolvedPath := replacePathParams(path)
		for method := range methods {
			endpoints = append(endpoints, config.Endpoint{
				Method: strings.ToUpper(method),
				URL:    resolvedPath,
			})
		}
	}
	return endpoints
}
