package data

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const osvAPI = "https://api.osv.dev/v1/query"

type CVE struct {
	ID       string
	Summary  string
	Severity string
	URL      string
}

type osvRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"vulns"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func QueryVulns(name, version string) ([]CVE, error) {
	ecosystems := []string{"Homebrew", "OSS-Fuzz"}
	seen := map[string]bool{}
	var cves []CVE

	for _, eco := range ecosystems {
		req := osvRequest{
			Package: osvPackage{Name: name, Ecosystem: eco},
			Version: version,
		}
		body, _ := json.Marshal(req)
		resp, err := httpClient.Post(osvAPI, "application/json", bytes.NewReader(body))
		if err != nil {
			continue
		}
		var result osvResponse
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		for _, v := range result.Vulns {
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true

			severity := "unknown"
			for _, s := range v.Severity {
				if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
					severity = scoreSeverity(s.Score)
					break
				}
			}

			url := fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID)
			if len(v.References) > 0 {
				url = v.References[0].URL
			}

			cves = append(cves, CVE{
				ID:       v.ID,
				Summary:  truncate(v.Summary, 80),
				Severity: severity,
				URL:      url,
			})
		}
	}
	return cves, nil
}

func scoreSeverity(score string) string {
	// CVSS score is like "CVSS:3.1/AV:N/AC:L/..." — extract base score from end
	// Or it might be a plain float string
	var f float64
	fmt.Sscanf(score, "%f", &f)
	switch {
	case f >= 9.0:
		return "critical"
	case f >= 7.0:
		return "high"
	case f >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
