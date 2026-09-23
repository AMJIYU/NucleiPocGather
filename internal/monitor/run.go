package monitor

import (
	"context"
	"log"
	"path/filepath"
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

	writer, err := newOutputWriter(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := writer.close(); runErr == nil && closeErr != nil {
			runErr = closeErr
		}
	}()

	var files []evaluated
	for _, source := range sources {
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
		for _, path := range paths {
			if cfg.Limit > 0 && len(files) >= cfg.Limit {
				break
			}
			files = append(files, evaluated{Path: path, Source: source})
		}
		log.Printf("[INFO] source=%s templates=%d", source.Name, len(paths))
		if cfg.Limit > 0 && len(files) >= cfg.Limit {
			break
		}
	}

	if len(files) == 0 {
		return gerror.New("no YAML templates discovered from configured sources")
	}
	if err := evaluateTemplates(parent, cfg, files); err != nil {
		return err
	}

	summary := Summary{
		GeneratedAt:    now(),
		Categories:     make(map[string]int),
		IncompatibleBy: make(map[string]int),
		Severities:     make(map[string]int),
	}
	for _, item := range files {
		summary.Total++
		if item.Record.Status == "compatible" {
			categories := categoriesFor(item.Record.RelativePath, item.Meta)
			paths, duplicate, writeErr := writer.writeCompatible(item, categories)
			if writeErr != nil {
				return writeErr
			}
			item.Record.Categories = categories
			item.Record.OutputPaths = paths
			if duplicate {
				summary.Duplicates++
			}
			summary.Compatible++
			for _, category := range categories {
				summary.Categories[category]++
			}
			severity := item.Meta.Severity
			if severity == "" {
				severity = "unknown"
			}
			summary.Severities[severity]++
		} else {
			path, writeErr := writer.writeIncompatible(item, item.Record.Reason)
			if writeErr != nil {
				return writeErr
			}
			item.Record.OutputPaths = []string{path}
			summary.Incompatible++
			summary.IncompatibleBy[item.Record.Reason]++
		}
		if err := writer.writeRecord(item.Record); err != nil {
			return err
		}
	}
	if err := writeSummary(cfg.MetadataDir, summary); err != nil {
		return err
	}
	log.Printf("[INFO] total=%d compatible=%d incompatible=%d duplicates=%d", summary.Total, summary.Compatible, summary.Incompatible, summary.Duplicates)
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
