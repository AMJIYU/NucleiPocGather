package monitor

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"
)

type outputWriter struct {
	compatibleDir   string
	incompatibleDir string
	manifest        *os.File
	manifestWriter  *bufio.Writer
	seen            map[string]map[string]struct{}
	mu              sync.Mutex
}

func newOutputWriter(cfg Config) (*outputWriter, error) {
	if cfg.CleanOutput {
		for _, path := range []string{cfg.CompatibleDir, cfg.IncompatibleDir, cfg.MetadataDir} {
			if err := os.RemoveAll(path); err != nil {
				return nil, gerror.Wrapf(err, "clean generated directory %q", path)
			}
		}
	}
	for _, path := range []string{cfg.CompatibleDir, cfg.IncompatibleDir, cfg.MetadataDir} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return nil, gerror.Wrapf(err, "create generated directory %q", path)
		}
	}
	manifestPath := filepath.Join(cfg.MetadataDir, "manifest.jsonl")
	manifest, err := os.Create(manifestPath)
	if err != nil {
		return nil, gerror.Wrapf(err, "create manifest %q", manifestPath)
	}
	return &outputWriter{
		compatibleDir:   cfg.CompatibleDir,
		incompatibleDir: cfg.IncompatibleDir,
		manifest:        manifest,
		manifestWriter:  bufio.NewWriter(manifest),
		seen:            make(map[string]map[string]struct{}),
	}, nil
}

func (writer *outputWriter) close() error {
	if err := writer.manifestWriter.Flush(); err != nil {
		_ = writer.manifest.Close()
		return gerror.Wrap(err, "flush manifest")
	}
	if err := writer.manifest.Close(); err != nil {
		return gerror.Wrap(err, "close manifest")
	}
	return nil
}

func (writer *outputWriter) writeCompatible(item evaluated, categories []string) (paths []string, duplicate bool, err error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, category := range categories {
		if writer.seen[category] == nil {
			writer.seen[category] = make(map[string]struct{})
		}
		if _, exists := writer.seen[category][item.Hash]; exists {
			duplicate = true
			continue
		}
		destinationDir := filepath.Join(writer.compatibleDir, category)
		if err := os.MkdirAll(destinationDir, 0o755); err != nil {
			return nil, false, gerror.Wrapf(err, "create category directory %q", destinationDir)
		}
		destination := uniqueDestination(destinationDir, filepath.Base(item.Path), item.Hash)
		if err := copyFile(item.Path, destination); err != nil {
			return nil, false, err
		}
		writer.seen[category][item.Hash] = struct{}{}
		paths = append(paths, filepath.ToSlash(filepath.Join(category, filepath.Base(destination))))
	}
	return paths, duplicate, nil
}

func (writer *outputWriter) writeIncompatible(item evaluated, reason string) (string, error) {
	directory := filepath.Join(writer.incompatibleDir, safeName(reason))
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", gerror.Wrapf(err, "create incompatible directory %q", directory)
	}
	destination := uniqueDestination(directory, filepath.Base(item.Path), item.Hash)
	if err := copyFile(item.Path, destination); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(safeName(reason), filepath.Base(destination))), nil
}

func (writer *outputWriter) writeRecord(record Record) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	encoded, err := json.Marshal(record)
	if err != nil {
		return gerror.Wrap(err, "encode manifest record")
	}
	if _, err := writer.manifestWriter.Write(append(encoded, '\n')); err != nil {
		return gerror.Wrap(err, "write manifest record")
	}
	return nil
}

func copyFile(source, destination string) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return gerror.Wrapf(err, "read template %q", source)
	}
	if err := os.WriteFile(destination, content, 0o644); err != nil {
		return gerror.Wrapf(err, "write template %q", destination)
	}
	return nil
}

func uniqueDestination(directory, base, hash string) string {
	base = safeName(base)
	destination := filepath.Join(directory, base)
	if _, err := os.Stat(destination); os.IsNotExist(err) {
		return destination
	}
	extension := filepath.Ext(base)
	stem := strings.TrimSuffix(base, extension)
	return filepath.Join(directory, stem+"-"+hash[:12]+extension)
}

func writeSummary(dir string, summary Summary) error {
	if summary.Categories == nil {
		summary.Categories = map[string]int{}
	}
	if summary.IncompatibleBy == nil {
		summary.IncompatibleBy = map[string]int{}
	}
	if summary.Severities == nil {
		summary.Severities = map[string]int{}
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return gerror.Wrap(err, "encode summary")
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), append(encoded, '\n'), 0o644); err != nil {
		return gerror.Wrap(err, "write summary")
	}
	return nil
}

func sortedKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func now() time.Time { return time.Now().UTC() }
