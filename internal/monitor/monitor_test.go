package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseTemplateAndClassify(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "CVE-2024-1234.yaml")
	content := []byte(`id: CVE-2024-1234
info:
  name: Example WordPress SSRF
  author: test
  severity: Hight
  tags: cve,wordpress,ssrf
http:
  - method: GET
    path:
      - "{{BaseURL}}/health"
    matchers:
      - type: status
        status: [200]
`)
	if err := os.WriteFile(templatePath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	meta, err := parseTemplate(templatePath)
	if err != nil {
		t.Fatalf("parseTemplate() error = %v", err)
	}
	if meta.ID != "CVE-2024-1234" || meta.Severity != "high" || meta.Protocol != "http" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
	categories := categoriesFor("plugins/wordpress/CVE-2024-1234.yaml", meta)
	for _, expected := range []string{"cve", "wordpress", "ssrf"} {
		if !contains(categories, expected) {
			t.Errorf("categories %v does not contain %q", categories, expected)
		}
	}
}

func TestParseTemplateRejectsNonNucleiYAML(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(templatePath, []byte("name: not-a-template\nvalue: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseTemplate(templatePath); err == nil {
		t.Fatal("parseTemplate() expected an error")
	}
}

func TestSafeName(t *testing.T) {
	if got := safeName("owner/repo with spaces"); got != "owner_repo_with_spaces" {
		t.Fatalf("safeName() = %q", got)
	}
}

func TestLoadStateRoundTrip(t *testing.T) {
	metadataDir := t.TempDir()
	record := Record{
		Source:       "owner__repo",
		SourceURL:    "https://github.com/owner/repo",
		RelativePath: "templates/example.yaml",
		Status:       "compatible",
		SHA256:       "abc123",
		OutputPaths:  []string{"detect/example.yaml"},
		ProcessedAt:  time.Now().UTC(),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadataDir, "manifest.jsonl"), append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	wantedState := map[string]SourceState{
		"https://github.com/owner/repo": {
			URL:      "https://github.com/owner/repo",
			Name:     "owner__repo",
			Revision: "0123456789abcdef",
		},
	}
	if err := writeState(metadataDir, wantedState); err != nil {
		t.Fatal(err)
	}

	records, states, hasManifest, err := loadState(metadataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !hasManifest || len(records) != 1 || len(states) != 1 {
		t.Fatalf("unexpected state: hasManifest=%v records=%d states=%d", hasManifest, len(records), len(states))
	}
	key := recordKey(record.SourceURL, record.RelativePath)
	if records[key].SHA256 != record.SHA256 || states[record.SourceURL].Revision != wantedState[record.SourceURL].Revision {
		t.Fatalf("state did not round-trip: records=%+v states=%+v", records, states)
	}
}

func TestShortRevision(t *testing.T) {
	if got := shortRevision("0123456789abcdef"); got != "0123456789ab" {
		t.Fatalf("shortRevision() = %q", got)
	}
	if got := shortRevision("short"); got != "short" {
		t.Fatalf("shortRevision() changed short value to %q", got)
	}
}

func TestSourceOutputsExist(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.CompatibleDir = filepath.Join(root, "poc")
	cfg.IncompatibleDir = filepath.Join(root, "incompatible")
	records := map[string]Record{
		"one": {
			SourceURL:   "https://github.com/owner/repo",
			Status:      "compatible",
			OutputPaths: []string{"http/example.yaml"},
		},
	}
	if sourceOutputsExist(cfg, records, "https://github.com/owner/repo") {
		t.Fatal("sourceOutputsExist() reported missing output as present")
	}
	if err := os.MkdirAll(filepath.Join(cfg.CompatibleDir, "http"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.CompatibleDir, "http", "example.yaml"), []byte("id: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !sourceOutputsExist(cfg, records, "https://github.com/owner/repo") {
		t.Fatal("sourceOutputsExist() reported existing output as missing")
	}
}

func TestOutputWriterReusesDuplicateOutput(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.CompatibleDir = filepath.Join(root, "poc")
	cfg.IncompatibleDir = filepath.Join(root, "incompatible")
	cfg.MetadataDir = filepath.Join(root, "metadata")
	cfg.CleanOutput = true
	templatePath := filepath.Join(root, "example.yaml")
	if err := os.WriteFile(templatePath, []byte("id: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	writer, err := newOutputWriter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	item := evaluated{Path: templatePath, Hash: "0123456789abcdef"}
	paths, duplicate, err := writer.writeCompatible(item, []string{"http"})
	if err != nil {
		t.Fatal(err)
	}
	if duplicate || len(paths) != 1 {
		t.Fatalf("initial write returned duplicate=%v paths=%v", duplicate, paths)
	}
	if err := writer.close(); err != nil {
		t.Fatal(err)
	}

	cfg.CleanOutput = false
	writer, err = newOutputWriter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writer.seed(map[string]Record{
		"first": {
			Status:      "compatible",
			SHA256:      item.Hash,
			Categories:  []string{"http"},
			OutputPaths: paths,
		},
	})
	reused, duplicate, err := writer.writeCompatible(item, []string{"http"})
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate || len(reused) != 1 || reused[0] != paths[0] {
		t.Fatalf("duplicate write did not reuse output: duplicate=%v reused=%v original=%v", duplicate, reused, paths)
	}
	if err := writer.close(); err != nil {
		t.Fatal(err)
	}
}

func TestDeduplicateCompatibleOutput(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "cve", "first.yaml")
	second := filepath.Join(root, "ssrf", "second.yaml")
	unique := filepath.Join(root, "other", "unique.yaml")
	for _, path := range []string{first, second, unique} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(first, []byte("id: duplicate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("id: duplicate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unique, []byte("id: unique\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	records := map[string]Record{
		"duplicate": {
			Status:      "compatible",
			OutputPaths: []string{"ssrf/second.yaml"},
		},
	}
	removed, err := deduplicateCompatibleOutput(root, records)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("deduplicateCompatibleOutput() removed %d files, want 1", removed)
	}
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatalf("duplicate output still exists, stat error = %v", err)
	}
	if got := records["duplicate"].OutputPaths; len(got) != 1 || got[0] != "cve/first.yaml" {
		t.Fatalf("manifest output path = %v, want [cve/first.yaml]", got)
	}
}

func TestSummarizeRecordsCountsCurrentDuplicates(t *testing.T) {
	records := map[string]Record{
		"first": {
			Status:     "compatible",
			SHA256:     "same",
			Categories: []string{"http"},
		},
		"second": {
			Status:     "compatible",
			SHA256:     "same",
			Categories: []string{"http"},
		},
		"third": {
			Status:     "compatible",
			SHA256:     "different",
			Categories: []string{"http"},
		},
	}
	summary := summarizeRecords(records)
	if summary.Duplicates != 1 {
		t.Fatalf("summarizeRecords() duplicates = %d, want 1", summary.Duplicates)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
