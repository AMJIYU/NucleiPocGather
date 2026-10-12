package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/gogf/gf/v2/errors/gerror"
)

func loadState(metadataDir string) (map[string]Record, map[string]SourceState, bool, error) {
	sources := make(map[string]SourceState)
	records, hasManifest, err := loadManifest(metadataDir)
	if err != nil {
		return nil, nil, false, err
	}
	if !hasManifest {
		return records, sources, false, nil
	}

	sourcesPath := filepath.Join(metadataDir, "sources.json")
	encoded, err := os.ReadFile(sourcesPath)
	if os.IsNotExist(err) {
		return records, sources, hasManifest, nil
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
	return records, sources, hasManifest, nil
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

func writeProgress(metadataDir string, moreWork bool, processed int) error {
	progress := struct {
		MoreWork  bool `json:"more_work"`
		Processed int  `json:"processed"`
	}{MoreWork: moreWork, Processed: processed}
	encoded, err := json.MarshalIndent(progress, "", "  ")
	if err != nil {
		return gerror.Wrap(err, "encode run progress")
	}
	if err := os.WriteFile(filepath.Join(metadataDir, "progress.json"), append(encoded, '\n'), 0o644); err != nil {
		return gerror.Wrap(err, "write run progress")
	}
	return nil
}

func recordKey(sourceURL, relativePath string) string {
	return sourceURL + "\x00" + relativePath
}
