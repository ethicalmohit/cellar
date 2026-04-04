package data

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	osvQueryAPI = "https://api.osv.dev/v1/query"
	osvBatchAPI = "https://api.osv.dev/v1/querybatch"
)

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

type osvBatchRequest struct {
	Queries []osvRequest `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvResponse `json:"results"`
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// QueryVulnsBatch sends a single POST /v1/querybatch request covering all
// packages × ecosystems, replacing the previous O(N) sequential HTTP loop.
// Returns a map of package name → CVEs found.
func QueryVulnsBatch(pkgs []Package) map[string][]CVE {
	if len(pkgs) == 0 {
		return nil
	}
	ecosystems := []string{"Homebrew", "OSS-Fuzz"}
	queries := make([]osvRequest, 0, len(pkgs)*len(ecosystems))
	for _, p := range pkgs {
		for _, eco := range ecosystems {
			queries = append(queries, osvRequest{
				Package: osvPackage{Name: p.Name, Ecosystem: eco},
				Version: p.Version,
			})
		}
	}

	body, _ := json.Marshal(osvBatchRequest{Queries: queries})
	resp, err := httpClient.Post(osvBatchAPI, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var result osvBatchResponse
	json.NewDecoder(resp.Body).Decode(&result)

	cveMap := make(map[string][]CVE)
	seenIDs := make(map[string]map[string]bool)

	for i, r := range result.Results {
		if i >= len(queries) {
			break
		}
		pkgName := queries[i].Package.Name
		if seenIDs[pkgName] == nil {
			seenIDs[pkgName] = make(map[string]bool)
		}
		for _, v := range r.Vulns {
			if seenIDs[pkgName][v.ID] {
				continue
			}
			seenIDs[pkgName][v.ID] = true

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

			cveMap[pkgName] = append(cveMap[pkgName], CVE{
				ID:       v.ID,
				Summary:  truncate(v.Summary, 80),
				Severity: severity,
				URL:      url,
			})
		}
	}
	return cveMap
}

func scoreSeverity(score string) string {
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
