package monitor

import "time"

// Config controls one complete collection run.
type Config struct {
	SourcesFile     string
	Workspace       string
	CompatibleDir   string
	IncompatibleDir string
	MetadataDir     string
	NucleiBin       string
	Workers         int
	Limit           int
	CommandTimeout  time.Duration
	CleanOutput     bool
}

func DefaultConfig() Config {
	return Config{
		SourcesFile:     "repo.txt",
		Workspace:       ".cache/nuclei-poc-sources",
		CompatibleDir:   "poc",
		IncompatibleDir: "incompatible",
		MetadataDir:     "metadata",
		NucleiBin:       "nuclei",
		Workers:         4,
		CommandTimeout:  2 * time.Minute,
		CleanOutput:     false,
	}
}
