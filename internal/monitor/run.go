package monitor

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"
)

func Run(parent context.Context, cfg Config) (runErr error) {
	deadline := time.Now().Add(cfg.MaxRunDuration)
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

	moreWork := false
	for sourceIndex, source := range sources {
		if cfg.Limit > 0 && len(changedItems) >= cfg.Limit {
			moreWork = true
			log.Printf("[INFO] limit=%d reached before source=%s", cfg.Limit, source.Name)
			break
		}
		revision, revisionErr := sourceRevision(parent, source, cfg.CommandTimeout)
		if revisionErr != nil {
			log.Printf("[WARN] %s", revisionErr)
			continue
		}
		previousState := sourceStates[source.URL]
		outputsExist := sourceOutputsExist(cfg, previous, source.URL)
		if previousState.Revision == revision && previousState.Complete && !fullRebuild && outputsExist {
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

		previousSource := recordsForSource(records, source.URL)
		currentPaths := make(map[string]struct{}, len(paths))
		for _, path := range paths {
			currentPaths[recordKey(source.URL, relativePath(root, path))] = struct{}{}
		}
		cursor := ""
		if previousState.Revision == revision && !previousState.Complete && outputsExist && !fullRebuild {
			cursor = previousState.Cursor
		}
		limited := false
		sourceChanged := 0
		for pathIndex, path := range paths {
			relative := relativePath(root, path)
			if cursor != "" && relative <= cursor {
				continue
			}
			key := recordKey(source.URL, relative)
			hash, hashErr := hashFile(path)
			if hashErr != nil {
				return hashErr
			}
			old, exists := previousSource[key]
			if exists && old.SHA256 == hash && recordOutputsExist(cfg, old) && !fullRebuild {
				continue
			}
			if exists {
				removedRecords[key] = old
				delete(records, key)
			}
			changedItems = append(changedItems, evaluated{Path: path, Source: source, Hash: hash})
			sourceChanged++
			if cfg.Limit > 0 && len(changedItems) >= cfg.Limit && pathIndex+1 < len(paths) {
				nextSourceStates[source.URL] = SourceState{URL: source.URL, Name: source.Name, Revision: revision, Cursor: relative, UpdatedAt: now()}
				limited = true
				moreWork = true
				break
			}
		}
		if limited {
			log.Printf("[INFO] source=%s paused at %s; changed=%d", source.Name, nextSourceStates[source.URL].Cursor, sourceChanged)
			break
		}
		for key, old := range previousSource {
			if _, exists := currentPaths[key]; !exists {
				removedRecords[key] = old
				delete(records, key)
			}
		}
		nextSourceStates[source.URL] = SourceState{
			URL:       source.URL,
			Name:      source.Name,
			Revision:  revision,
			Complete:  true,
			UpdatedAt: now(),
		}
		log.Printf("[INFO] source=%s revision=%s templates=%d changed=%d", source.Name, shortRevision(revision), len(paths), sourceChanged)
		if cfg.Limit > 0 && len(changedItems) >= cfg.Limit && sourceIndex+1 < len(sources) {
			moreWork = true
			break
		}
	}

	if len(changedItems) > 0 {
		validationContext, cancel := context.WithDeadline(parent, deadline)
		evaluationErr := evaluateTemplates(parent, validationContext, cfg, changedItems)
		cancel()
		if evaluationErr != nil {
			if !errors.Is(evaluationErr, context.DeadlineExceeded) || parent.Err() != nil {
				return evaluationErr
			}
			moreWork = true
			log.Printf("[INFO] run time budget reached; saving completed validation results")
		}
		changedItems = completedItems(changedItems, previous, records, removedRecords, nextSourceStates)
	}
	if len(records) == 0 && len(changedItems) == 0 {
		return gerror.New("no YAML templates available from configured sources")
	}

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
	if _, err := deduplicateCompatibleOutput(cfg.CompatibleDir, records); err != nil {
		return err
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
	if err := writeProgress(cfg.MetadataDir, moreWork, len(changedItems)); err != nil {
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
	if cfg.ValidationBatchSize < 1 {
		return gerror.New("validation batch size must be greater than zero")
	}
	if cfg.CommandTimeout <= 0 {
		return gerror.New("command timeout must be greater than zero")
	}
	if cfg.MaxRunDuration <= 0 {
		return gerror.New("max run duration must be greater than zero")
	}
	for _, path := range []string{cfg.CompatibleDir, cfg.IncompatibleDir, cfg.MetadataDir} {
		if strings.TrimSpace(path) == "" {
			return gerror.New("output paths cannot be empty")
		}
	}
	return nil
}

func completedItems(items []evaluated, previous, records, removed map[string]Record, states map[string]SourceState) []evaluated {
	completed := make([]evaluated, 0, len(items))
	for _, item := range items {
		if item.Record.Status == "compatible" || item.Record.Status == "incompatible" {
			completed = append(completed, item)
			continue
		}
		relative := item.Record.RelativePath
		if relative == "" {
			continue
		}
		key := recordKey(item.Source.URL, relative)
		if old, exists := previous[key]; exists {
			records[key] = old
			delete(removed, key)
		}
		state := states[item.Source.URL]
		state.Cursor = ""
		state.Complete = false
		states[item.Source.URL] = state
	}
	return completed
}

func evaluateTemplates(parent, validationContext context.Context, cfg Config, items []evaluated) error {
	if err := prepareTemplates(parent, cfg, items); err != nil {
		return err
	}
	groups := make([]*validationGroup, 0)
	byHash := make(map[string]*validationGroup)
	for index := range items {
		item := &items[index]
		if item.Record.Status != "pending" {
			continue
		}
		group, exists := byHash[item.Hash]
		if !exists {
			group = &validationGroup{}
			byHash[item.Hash] = group
			groups = append(groups, group)
		}
		group.Members = append(group.Members, item)
	}
	if len(groups) == 0 {
		return nil
	}
	log.Printf("[INFO] validation candidates=%d unique=%d batch-size=%d", len(items), len(groups), cfg.ValidationBatchSize)
	return validateGroups(validationContext, cfg, groups)
}

func prepareTemplates(parent context.Context, cfg Config, items []evaluated) error {
	jobs := make(chan *evaluated)
	workerErrors := make(chan error, 1)
	var workers sync.WaitGroup
	for index := 0; index < cfg.Workers; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				if err := prepareItem(cfg, item); err != nil {
					select {
					case workerErrors <- err:
					default:
					}
					continue
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

func validateGroups(parent context.Context, cfg Config, groups []*validationGroup) error {
	jobs := make(chan []*validationGroup)
	workerErrors := make(chan error, 1)
	var processed atomic.Int64
	var workers sync.WaitGroup
	total := 0
	for _, group := range groups {
		total += len(group.Members)
	}
	for index := 0; index < cfg.Workers; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for batch := range jobs {
				if err := validateGroupBatch(parent, cfg, batch, &processed, total); err != nil {
					select {
					case workerErrors <- err:
					default:
					}
				}
			}
		}()
	}
	for start := 0; start < len(groups); start += cfg.ValidationBatchSize {
		end := start + cfg.ValidationBatchSize
		if end > len(groups) {
			end = len(groups)
		}
		select {
		case jobs <- groups[start:end]:
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

func validateGroupBatch(parent context.Context, cfg Config, groups []*validationGroup, processed *atomic.Int64, total int) error {
	if len(groups) == 0 {
		return nil
	}
	if err := parent.Err(); err != nil {
		return gerror.Wrap(err, "template evaluation cancelled")
	}
	paths := make([]string, 0, len(groups))
	for _, group := range groups {
		paths = append(paths, group.Members[0].Path)
	}
	failed, validationErr := validateBatchWithNuclei(parent, cfg, paths)
	if validationErr != nil && errors.Is(validationErr, context.DeadlineExceeded) && parent.Err() == nil {
		if len(groups) == 1 {
			markGroup(groups[0], "incompatible", "nuclei_validation_timeout", truncate(validationErr.Error(), 800))
			logValidationProgress(processed.Add(int64(groupSize(groups))), total)
			return nil
		}
		middle := len(groups) / 2
		if err := validateGroupBatch(parent, cfg, groups[:middle], processed, total); err != nil {
			return err
		}
		return validateGroupBatch(parent, cfg, groups[middle:], processed, total)
	}
	if !failed {
		if validationErr != nil {
			return validationErr
		}
		for _, group := range groups {
			markGroup(group, "compatible", "", "")
		}
		logValidationProgress(processed.Add(int64(groupSize(groups))), total)
		return nil
	}
	if len(groups) == 1 {
		message := "nuclei validation failed"
		if validationErr != nil {
			message = truncate(validationErr.Error(), 800)
		}
		markGroup(groups[0], "incompatible", "nuclei_validation", message)
		logValidationProgress(processed.Add(int64(groupSize(groups))), total)
		return nil
	}
	middle := len(groups) / 2
	if err := validateGroupBatch(parent, cfg, groups[:middle], processed, total); err != nil {
		return err
	}
	return validateGroupBatch(parent, cfg, groups[middle:], processed, total)
}

func prepareItem(cfg Config, item *evaluated) error {
	hash := item.Hash
	var err error
	if hash == "" {
		hash, err = hashFile(item.Path)
	}
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
		Status:       "pending",
	}
	if err != nil {
		item.Record.Status = "incompatible"
		item.Record.Reason = "yaml_or_structure"
		item.Record.Message = truncate(err.Error(), 800)
		return nil
	}
	return nil
}

func evaluateOne(parent context.Context, cfg Config, item *evaluated) error {
	if err := prepareItem(cfg, item); err != nil {
		return err
	}
	if item.Record.Status != "pending" {
		return nil
	}
	if err := validateWithNuclei(parent, cfg, item.Path); err != nil {
		markGroup(&validationGroup{Members: []*evaluated{item}}, "incompatible", "nuclei_validation", truncate(err.Error(), 800))
		return nil
	}
	item.Record.Status = "compatible"
	return nil
}

func markGroup(group *validationGroup, status, reason, message string) {
	for _, item := range group.Members {
		item.Record.Status = status
		item.Record.Reason = reason
		item.Record.Message = message
	}
}

func groupSize(groups []*validationGroup) int {
	size := 0
	for _, group := range groups {
		size += len(group.Members)
	}
	return size
}

func logValidationProgress(processed int64, total int) {
	if processed >= int64(total) || processed%10000 < 1000 {
		log.Printf("[INFO] validated=%d/%d", processed, total)
	}
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

func deduplicateCompatibleOutput(root string, records map[string]Record) (int, error) {
	paths, err := templateFiles(root)
	if err != nil {
		return 0, err
	}
	canonical := make(map[string]string)
	replacements := make(map[string]string)
	removed := 0
	for _, path := range paths {
		relative := relativePath(root, path)
		hash, hashErr := hashFile(path)
		if hashErr != nil {
			return removed, hashErr
		}
		if original, exists := canonical[hash]; exists {
			if removeErr := os.Remove(path); removeErr != nil {
				return removed, gerror.Wrapf(removeErr, "remove duplicate template %q", path)
			}
			replacements[relative] = original
			removed++
			continue
		}
		canonical[hash] = relative
	}
	for key, record := range records {
		if record.Status != "compatible" {
			continue
		}
		paths := make([]string, 0, len(record.OutputPaths))
		for _, relative := range record.OutputPaths {
			if replacement, exists := replacements[relative]; exists {
				relative = replacement
			}
			if !containsString(paths, relative) {
				paths = append(paths, relative)
			}
		}
		record.OutputPaths = paths
		records[key] = record
	}
	return removed, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
