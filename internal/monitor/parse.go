package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
	"gopkg.in/yaml.v3"
)

var protocolKeys = []string{
	"http", "dns", "tcp", "network", "headless", "file", "websocket", "whois", "ssl",
	"code", "javascript", "flow", "workflow", "requests",
}

func parseTemplate(path string) (TemplateMeta, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return TemplateMeta{}, gerror.Wrapf(err, "read template %q", path)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(content, &document); err != nil {
		return TemplateMeta{}, gerror.Wrap(err, "parse YAML")
	}
	if len(document) == 0 {
		return TemplateMeta{}, gerror.New("empty YAML document")
	}

	meta := TemplateMeta{}
	meta.ID, _ = document["id"].(string)
	meta.ID = strings.TrimSpace(meta.ID)
	if meta.ID == "" {
		return TemplateMeta{}, gerror.New("missing nuclei id")
	}
	info, ok := document["info"].(map[string]interface{})
	if !ok {
		return TemplateMeta{}, gerror.New("missing nuclei info mapping")
	}
	meta.Name, _ = info["name"].(string)
	meta.Name = strings.TrimSpace(meta.Name)
	meta.Severity, _ = info["severity"].(string)
	meta.Severity = normalizeSeverity(meta.Severity)
	meta.Tags = parseTags(info["tags"])

	for _, key := range protocolKeys {
		if value, exists := document[key]; exists && value != nil {
			meta.Protocol = key
			break
		}
	}
	if meta.Protocol == "" {
		return TemplateMeta{}, gerror.New("no supported nuclei protocol section")
	}
	return meta, nil
}

func parseTags(value interface{}) []string {
	var raw []string
	switch typed := value.(type) {
	case string:
		for _, tag := range strings.Split(typed, ",") {
			if cleaned := strings.TrimSpace(strings.ToLower(tag)); cleaned != "" {
				raw = append(raw, cleaned)
			}
		}
	case []interface{}:
		for _, item := range typed {
			if tag, ok := item.(string); ok && strings.TrimSpace(tag) != "" {
				raw = append(raw, strings.ToLower(strings.TrimSpace(tag)))
			}
		}
	}
	sort.Strings(raw)
	return raw
}

func normalizeSeverity(value string) string {
	severity := strings.ToLower(strings.TrimSpace(value))
	switch severity {
	case "critical", "high", "medium", "low", "info", "unknown":
		return severity
	case "meduim":
		return "medium"
	case "hight", "highx":
		return "high"
	case "cretical", "criticall", "ciritical", "cirtical", "severe":
		return "critical"
	case "informative":
		return "info"
	default:
		if severity == "" {
			return "unknown"
		}
		return severity
	}
}

func hashFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", gerror.Wrapf(err, "read file for hashing %q", path)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func templateFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if path != root && (strings.HasPrefix(info.Name(), ".") || info.Name() == "node_modules" || info.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		extension := strings.ToLower(filepath.Ext(path))
		if extension == ".yaml" || extension == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, gerror.Wrapf(err, "walk source %q", root)
	}
	sort.Strings(files)
	return files, nil
}

func relativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(relative)
}

func displayMeta(meta TemplateMeta) string {
	return fmt.Sprintf("%s (%s)", meta.ID, meta.Protocol)
}
