package monitor

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gogf/gf/v2/errors/gerror"
)

func Run(parent context.Context, cfg Config) (runErr error) {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	sources, err := readSources(cfg.SourcesFile)
	if err != nil {
		return err
	}
	cfg.Workspace, err = filepath.Abs(cfg.Workspace)
	if err != nil {
		return gerror.Wrap(err, "resolve source workspace path")
	}

	previous, sourceStates, hasManifest, err := loadState(cfg.MetadataDir)
	if err != nil {
		return err
	}
	fullRebuild := cfg.CleanOutput || !hasManifest
	if fullRebuild {
		previous = make(map[string]Record)
		sourceStates = make(map[string]SourceState)
	}
	records := cloneRecords(previous)
	nextSourceStates := cloneSourceStates(sourceStates)
	changedItems := make([]evaluated, 0)
	removedRecords := make(map[string]Record)
	configuredSources := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		configuredSources[source.URL] = struct{}{}
	}
	if !fullRebuild {
		for key, record := range records {
			if _, configured := configuredSources[record.SourceURL]; configured {
				continue
			}
			removedRecords[key] = record
			delete(records, key)
		}
		for sourceURL := range nextSourceStates {
			if _, configured := configuredSources[sourceURL]; !configured {
				delete(nextSourceStates, sourceURL)
			}
		}
	}

	selectedTotal := 0
	for _, source := range sources {
		if cfg.Limit > 0 && selectedTotal >= cfg.Limit {
			break
		}
		revision, revisionErr := sourceRevision(parent, source, cfg.CommandTimeout)
		if revisionErr != nil {
			log.Printf("[WARN] %s", revisionErr)
			continue
		}
		if previousState, ok := sourceStates[source.URL]; ok && previousState.Revision == revision && !fullRebuild && sourceOutputsExist(cfg, previous, source.URL) {
			log.Printf("[SKIP] source=%s revision=%s unchanged", source.Name, shortRevision(revision))
			continue
		}

		root, syncErr := syncSource(parent, source, cfg.Workspace, cfg.CommandTimeout)
		if syncErr != nil {
			log.Printf("[WARN] %s", syncErr)
			continue
		}
		paths, walkErr := templateFiles(root)
		if walkErr != nil {
			log.Printf("[WARN] %s", walkErr)
			continue
		}

		previousSource := recordsForSource(previous, source.URL)
		currentSource := make(map[string]Record)
		limited := false
		sourceChanged := 0
		for _, path := range paths {
			if cfg.Limit > 0 && selectedTotal >= cfg.Limit {
				limited = true
				break
			}
			selectedTotal++
			relative := relativePath(root, path)
			key := recordKey(source.URL, relative)
			hash, hashErr := hashFile(path)
			if hashErr != nil {
				return hashErr
			}
			old, exists := previousSource[key]
			if exists && old.SHA256 == hash && recordOutputsExist(cfg, old) && !fullRebuild {
				currentSource[key] = old
				continue
			}
			if exists {
				removedRecords[key] = old
			}
			changedItems = append(changedItems, evaluated{Path: path, Source: source})
			sourceChanged++
		}
		if limited {
			for key, record := range currentSource {
				records[key] = record
			}
			log.Printf("[INFO] limit=%d reached; source state is not advanced", cfg.Limit)
			break
		}
		for key, old := range previousSource {
			if _, exists := currentSource[key]; !exists {
				removedRecords[key] = old
			}
		}
		for key := range previousSource {
			delete(records, key)
		}
		for key, record := range currentSource {
			records[key] = record
		}
		nextSourceStates[source.URL] = SourceState{
			URL:       source.URL,
			Name:      source.Name,
			Revision:  revision,
			UpdatedAt: now(),
		}
		log.Printf("[INFO] source=%s revision=%s templates=%d changed=%d", source.Name, shortRevision(revision), len(paths), sourceChanged)
	}

	if len(changedItems) > 0 {
		if err := evaluateTemplates(parent, cfg, changedItems); err != nil {
			return err
		}
	}
	if len(records) == 0 && len(changedItems) == 0 {
		return gerror.New("no YAML templates available from configured sources")
	}

	cfg.CleanOutput = fullRebuild
	writer, err := newOutputWriter(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := writer.close(); runErr == nil && closeErr != nil {
			runErr = closeErr
		}
	}()
	writer.seed(records)
	if !fullRebuild {
		protected := protectedOutputPaths(records)
		for _, record := range removedRecords {
			if err := removeRecordOutputs(cfg, record, protected); err != nil {
				return err
			}
		}
	}

	for _, item := range changedItems {
		key := recordKey(item.Source.URL, item.Record.RelativePath)
		if item.Record.Status == "compatible" {
			categories := categoriesFor(item.Record.RelativePath, item.Meta)
			paths, _, writeErr := writer.writeCompatible(item, categories)
			if writeErr != nil {
				return writeErr
			}
			item.Record.Categories = categories
			item.Record.OutputPaths = paths
		} else {
			path, writeErr := writer.writeIncompatible(item, item.Record.Reason)
			if writeErr != nil {
				return writeErr
			}
			item.Record.OutputPaths = []string{path}
		}
		records[key] = item.Record
	}

	for _, key := range sortedRecordKeys(records) {
		if err := writer.writeRecord(records[key]); err != nil {
			return err
		}
	}
	summary := summarizeRecords(records)
	if err := writeSummary(cfg.MetadataDir, summary); err != nil {
		return err
	}
	if err := writeState(cfg.MetadataDir, nextSourceStates); err != nil {
		return err
	}
	log.Printf("[INFO] total=%d compatible=%d incompatible=%d changed=%d skipped=%d", summary.Total, summary.Compatible, summary.Incompatible, len(changedItems), summary.Total-len(changedItems))
	return nil
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.SourcesFile) == "" || strings.TrimSpace(cfg.Workspace) == "" {
		return gerror.New("sources and workspace paths are required")
	}
	if cfg.Workers < 1 {
		return gerror.New("workers must be greater than zero")
	}
	if cfg.CommandTimeout <= 0 {
		return gerror.New("command timeout must be greater than zero")
	}
	for _, path := range []string{cfg.CompatibleDir, cfg.IncompatibleDir, cfg.MetadataDir} {
		if strings.TrimSpace(path) == "" {
			return gerror.New("output paths cannot be empty")
		}
	}
	return nil
}

func evaluateTemplates(parent context.Context, cfg Config, items []evaluated) error {
	jobs := make(chan *evaluated)
	workerErrors := make(chan error, 1)
	var processed atomic.Int64
	var workers sync.WaitGroup
	for index := 0; index < cfg.Workers; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				if err := evaluateOne(parent, cfg, item); err != nil {
					select {
					case workerErrors <- err:
					default:
					}
					continue
				}
				count := processed.Add(1)
				if count%100 == 0 {
					log.Printf("[INFO] validated=%d/%d", count, len(items))
				}
			}
		}()
	}
	for index := range items {
		select {
		case jobs <- &items[index]:
		case err := <-workerErrors:
			close(jobs)
			workers.Wait()
			return err
		case <-parent.Done():
			close(jobs)
			workers.Wait()
			return gerror.Wrap(parent.Err(), "template evaluation cancelled")
		}
	}
	close(jobs)
	workers.Wait()
	select {
	case err := <-workerErrors:
		return err
	default:
		return nil
	}
}

func evaluateOne(parent context.Context, cfg Config, item *evaluated) error {
	hash, err := hashFile(item.Path)
	if err != nil {
		return err
	}
	item.Hash = hash
	meta, err := parseTemplate(item.Path)
	item.Meta = meta
	item.Record = Record{
		Source:       item.Source.Name,
		SourceURL:    item.Source.URL,
		RelativePath: relativePath(filepath.Join(cfg.Workspace, item.Source.Name), item.Path),
		ID:           meta.ID,
		Name:         meta.Name,
		Severity:     meta.Severity,
		Tags:         meta.Tags,
		Protocol:     meta.Protocol,
		SHA256:       item.Hash,
		ProcessedAt:  now(),
		Status:       "incompatible",
	}
	if err != nil {
		item.Record.Reason = "yaml_or_structure"
		item.Record.Message = truncate(err.Error(), 800)
		return nil
	}
	if err := validateWithNuclei(parent, cfg, item.Path); err != nil {
		item.Record.Reason = "nuclei_validation"
		item.Record.Message = truncate(err.Error(), 800)
		return nil
	}
	item.Record.Status = "compatible"
	return nil
}

func cloneRecords(input map[string]Record) map[string]Record {
	output := make(map[string]Record, len(input))
	for key, record := range input {
		output[key] = record
	}
	return output
}

func cloneSourceStates(input map[string]SourceState) map[string]SourceState {
	output := make(map[string]SourceState, len(input))
	for key, state := range input {
		output[key] = state
	}
	return output
}

func shortRevision(revision string) string {
	if len(revision) <= 12 {
		return revision
	}
	return revision[:12]
}

func recordsForSource(records map[string]Record, sourceURL string) map[string]Record {
	output := make(map[string]Record)
	for key, record := range records {
		if record.SourceURL == sourceURL {
			output[key] = record
		}
	}
	return output
}

func sortedRecordKeys(records map[string]Record) []string {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func recordOutputsExist(cfg Config, record Record) bool {
	if len(record.OutputPaths) == 0 {
		return false
	}
	root := cfg.IncompatibleDir
	if record.Status == "compatible" {
		root = cfg.CompatibleDir
	}
	for _, relative := range record.OutputPaths {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			return false
		}
	}
	return true
}

func sourceOutputsExist(cfg Config, records map[string]Record, sourceURL string) bool {
	for _, record := range records {
		if record.SourceURL == sourceURL && !recordOutputsExist(cfg, record) {
			return false
		}
	}
	return true
}

func protectedOutputPaths(records map[string]Record) map[string]struct{} {
	protected := make(map[string]struct{})
	for _, record := range records {
		root := "incompatible"
		if record.Status == "compatible" {
			root = "compatible"
		}
		for _, relative := range record.OutputPaths {
			protected[root+"\x00"+relative] = struct{}{}
		}
	}
	return protected
}

func removeRecordOutputs(cfg Config, record Record, protected map[string]struct{}) error {
	root := cfg.IncompatibleDir
	rootKey := "incompatible"
	if record.Status == "compatible" {
		root = cfg.CompatibleDir
		rootKey = "compatible"
	}
	for _, relative := range record.OutputPaths {
		if _, exists := protected[rootKey+"\x00"+relative]; exists {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return gerror.Wrapf(err, "remove stale template %q", path)
		}
	}
	return nil
}

func summarizeRecords(records map[string]Record) Summary {
	summary := Summary{
		GeneratedAt:    now(),
		Categories:     make(map[string]int),
		IncompatibleBy: make(map[string]int),
		Severities:     make(map[string]int),
	}
	seen := make(map[string]struct{})
	for _, record := range records {
		summary.Total++
		if record.Status == "compatible" {
			summary.Compatible++
			for _, category := range record.Categories {
				summary.Categories[category]++
			}
			severity := record.Severity
			if severity == "" {
				severity = "unknown"
			}
			summary.Severities[severity]++
			for _, category := range record.Categories {
				key := category + "\x00" + record.SHA256
				if _, exists := seen[key]; exists {
					summary.Duplicates++
					break
				}
				seen[key] = struct{}{}
			}
			continue
		}
		summary.Incompatible++
		summary.IncompatibleBy[record.Reason]++
	}
	return summary
}
