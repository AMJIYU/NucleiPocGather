package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
)

const (
	manifestBuckets       = 64
	manifestShardSize     = 8 << 20
	maxManifestRecordSize = 4 << 20
)

type manifestShard struct {
	file   *os.File
	writer *bufio.Writer
	part   int
	size   int
}

func loadManifest(metadataDir string) (map[string]Record, bool, error) {
	records := make(map[string]Record)
	manifestDir := filepath.Join(metadataDir, "manifest")
	entries, err := os.ReadDir(manifestDir)
	if err == nil {
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".jsonl") {
				continue
			}
			if !entry.Type().IsRegular() {
				return nil, false, gerror.Newf("manifest shard %q is not a regular file", entry.Name())
			}
			if err := readManifestRecords(filepath.Join(manifestDir, entry.Name()), records); err != nil {
				return nil, false, err
			}
		}
		return records, true, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, gerror.Wrapf(err, "read manifest directory %q", manifestDir)
	}
	legacyPath := filepath.Join(metadataDir, "manifest.jsonl")
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		return records, false, nil
	} else if err != nil {
		return nil, false, gerror.Wrapf(err, "stat legacy manifest %q", legacyPath)
	}
	if err := readManifestRecords(legacyPath, records); err != nil {
		return nil, false, err
	}
	return records, true, nil
}

func readManifestRecords(path string, records map[string]Record) error {
	file, err := os.Open(path)
	if err != nil {
		return gerror.Wrapf(err, "open manifest %q", path)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxManifestRecordSize)
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return gerror.Wrapf(err, "decode manifest record in %q", path)
		}
		key := recordKey(record.SourceURL, record.RelativePath)
		if _, exists := records[key]; exists {
			return gerror.Newf("duplicate manifest record %q in %q", key, path)
		}
		records[key] = record
	}
	if err := scanner.Err(); err != nil {
		return gerror.Wrapf(err, "read manifest %q", path)
	}
	return nil
}

func writeManifest(metadataDir string, records map[string]Record) error {
	return writeManifestWithShardSize(metadataDir, records, manifestShardSize)
}

func writeManifestWithShardSize(metadataDir string, records map[string]Record, maxShardSize int) error {
	tempDir, err := os.MkdirTemp(metadataDir, ".manifest-")
	if err != nil {
		return gerror.Wrap(err, "create temporary manifest directory")
	}
	defer os.RemoveAll(tempDir)

	shards := make(map[uint64]*manifestShard)
	defer func() {
		for _, shard := range shards {
			if shard.file != nil {
				_ = shard.file.Close()
			}
		}
	}()
	for _, key := range sortedRecordKeys(records) {
		encoded, err := json.Marshal(records[key])
		if err != nil {
			return gerror.Wrap(err, "encode manifest record")
		}
		line := append(encoded, '\n')
		if len(line) > maxShardSize || len(line) >= maxManifestRecordSize {
			return gerror.Newf("manifest record %q exceeds shard size limit", key)
		}
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(key))
		bucket := hash.Sum64() % manifestBuckets
		shard := shards[bucket]
		if shard == nil {
			shard = &manifestShard{}
			shards[bucket] = shard
		}
		if shard.file == nil || shard.size+len(line) > maxShardSize {
			if err := closeManifestShard(shard); err != nil {
				return err
			}
			if shard.size > 0 {
				shard.part++
			}
			path := filepath.Join(tempDir, fmt.Sprintf("%02x-%03d.jsonl", bucket, shard.part))
			file, err := os.Create(path)
			if err != nil {
				return gerror.Wrapf(err, "create manifest shard %q", path)
			}
			shard.file = file
			shard.writer = bufio.NewWriter(file)
			shard.size = 0
		}
		if _, err := shard.writer.Write(line); err != nil {
			return gerror.Wrap(err, "write manifest shard")
		}
		shard.size += len(line)
	}
	for _, shard := range shards {
		if err := closeManifestShard(shard); err != nil {
			return err
		}
	}

	manifestDir := filepath.Join(metadataDir, "manifest")
	backupDir := tempDir + "-previous"
	oldExists := false
	if err := os.Rename(manifestDir, backupDir); err == nil {
		oldExists = true
	} else if !os.IsNotExist(err) {
		return gerror.Wrap(err, "save previous manifest directory")
	}
	if err := os.Rename(tempDir, manifestDir); err != nil {
		if oldExists {
			_ = os.Rename(backupDir, manifestDir)
		}
		return gerror.Wrap(err, "publish manifest shards")
	}
	if oldExists {
		if err := os.RemoveAll(backupDir); err != nil {
			return gerror.Wrap(err, "remove previous manifest shards")
		}
	}
	legacyPath := filepath.Join(metadataDir, "manifest.jsonl")
	if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
		return gerror.Wrapf(err, "remove legacy manifest %q", legacyPath)
	}
	return nil
}

func closeManifestShard(shard *manifestShard) error {
	if shard.file == nil {
		return nil
	}
	if err := shard.writer.Flush(); err != nil {
		_ = shard.file.Close()
		shard.file = nil
		return gerror.Wrap(err, "flush manifest shard")
	}
	if err := shard.file.Close(); err != nil {
		shard.file = nil
		return gerror.Wrap(err, "close manifest shard")
	}
	shard.file = nil
	return nil
}
