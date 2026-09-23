package monitor

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/gogf/gf/v2/errors/gerror"
)

func loadState(metadataDir string) (map[string]Record, map[string]SourceState, bool, error) {
	records := make(map[string]Record)
	sources := make(map[string]SourceState)
	manifestPath := filepath.Join(metadataDir, "manifest.jsonl")
	manifest, err := os.Open(manifestPath)
	if os.IsNotExist(err) {
		return records, sources, false, nil
	}
	if err != nil {
		return nil, nil, false, gerror.Wrapf(err, "open previous manifest %q", manifestPath)
	}
	defer manifest.Close()

	scanner := bufio.NewScanner(manifest)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, nil, false, gerror.Wrap(err, "decode previous manifest record")
		}
		records[recordKey(record.SourceURL, record.RelativePath)] = record
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, false, gerror.Wrap(err, "read previous manifest")
	}

	sourcesPath := filepath.Join(metadataDir, "sources.json")
	encoded, err := os.ReadFile(sourcesPath)
	if os.IsNotExist(err) {
		return records, sources, true, nil
	}
	if err != nil {
		return nil, nil, false, gerror.Wrapf(err, "read source state %q", sourcesPath)
	}
	var sourceList []SourceState
	if err := json.Unmarshal(encoded, &sourceList); err != nil {
		return nil, nil, false, gerror.Wrap(err, "decode source state")
	}
	for _, source := range sourceList {
		sources[source.URL] = source
	}
	return records, sources, true, nil
}

func writeState(metadataDir string, sources map[string]SourceState) error {
	list := make([]SourceState, 0, len(sources))
	for _, source := range sources {
		list = append(list, source)
	}
	sort.Slice(list, func(left, right int) bool {
		return list[left].URL < list[right].URL
	})
	encoded, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return gerror.Wrap(err, "encode source state")
	}
	if err := os.WriteFile(filepath.Join(metadataDir, "sources.json"), append(encoded, '\n'), 0o644); err != nil {
		return gerror.Wrap(err, "write source state")
	}
	return nil
}

func recordKey(sourceURL, relativePath string) string {
	return sourceURL + "\x00" + relativePath
}
