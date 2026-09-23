package monitor

import (
	"os"
	"path/filepath"
	"testing"
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

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
