// Package report renders scanner output in the formats users consume: a human-friendly HTML dashboard,
// machine-readable findings JSON, a triage CSV, and SARIF for IDE/CI tooling. It is a pure render step
// and does not mutate findings.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Write emits the requested formats (html, json, csv, sarif) to outputDir along with the snapshot metadata side-file.
// It always writes metadata.json; unsupported format names return an error without partial cleanup.
func Write(outputDir string, formats []string, snapshot models.Snapshot, findings []models.Finding) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	written := make([]string, 0, len(formats))
	metadataPath, err := WriteMetadata(outputDir, snapshot.Metadata)
	if err != nil {
		return written, err
	}
	written = append(written, metadataPath)

	for _, format := range dedupeFormats(formats) {
		switch format {
		case "json":
			path := filepath.Join(outputDir, "findings.json")
			if err := writeJSON(path, findings); err != nil {
				return written, err
			}
			written = append(written, path)
		case "html":
			path := filepath.Join(outputDir, "report.html")
			if err := writeHTML(path, snapshot, findings); err != nil {
				return written, err
			}
			written = append(written, path)
		case "csv":
			path := filepath.Join(outputDir, "triage.csv")
			if err := writeCSV(path, findings); err != nil {
				return written, err
			}
			written = append(written, path)
		case "sarif":
			path := filepath.Join(outputDir, "findings.sarif")
			if err := writeSARIF(path, findings); err != nil {
				return written, err
			}
			written = append(written, path)
		default:
			return written, fmt.Errorf("unsupported output format %q", format)
		}
	}

	return written, nil
}

// dedupeFormats lower-cases, trims, and deduplicates the requested format list; an empty input defaults to html+json.
func dedupeFormats(formats []string) []string {
	if len(formats) == 0 {
		return []string{"html", "json"}
	}

	seen := map[string]struct{}{}
	result := make([]string, 0, len(formats))
	for _, format := range formats {
		format = strings.ToLower(strings.TrimSpace(format))
		if format == "" {
			continue
		}
		if _, ok := seen[format]; ok {
			continue
		}
		seen[format] = struct{}{}
		result = append(result, format)
	}

	sort.Strings(result)
	return result
}
