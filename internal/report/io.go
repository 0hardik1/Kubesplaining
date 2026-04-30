package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ReadFindings decodes a findings.json file written by Write into a slice of models.Finding.
func ReadFindings(path string) ([]models.Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open findings file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var findings []models.Finding
	if err := json.NewDecoder(file).Decode(&findings); err != nil {
		return nil, fmt.Errorf("decode findings file: %w", err)
	}

	return findings, nil
}

// WriteMetadata writes scan-metadata.json alongside the findings so future `report` invocations can reconstruct snapshot context.
func WriteMetadata(outputDir string, metadata models.SnapshotMetadata) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create metadata directory: %w", err)
	}

	path := filepath.Join(outputDir, "scan-metadata.json")
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create metadata file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(metadata); err != nil {
		return "", fmt.Errorf("encode metadata file: %w", err)
	}

	return path, nil
}

// ReadMetadata decodes a scan-metadata.json file back into a SnapshotMetadata value.
func ReadMetadata(path string) (models.SnapshotMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return models.SnapshotMetadata{}, fmt.Errorf("open metadata file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var metadata models.SnapshotMetadata
	if err := json.NewDecoder(file).Decode(&metadata); err != nil {
		return models.SnapshotMetadata{}, fmt.Errorf("decode metadata file: %w", err)
	}

	return metadata, nil
}

// GuessMetadataPath returns the default scan-metadata.json location for a findings file in the same directory.
func GuessMetadataPath(findingsPath string) string {
	return filepath.Join(filepath.Dir(findingsPath), "scan-metadata.json")
}
