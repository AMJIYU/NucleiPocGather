package main

import (
	"context"
	"flag"
	"log"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/AMJIYU/NucleiPocGather/internal/monitor"
)

func main() {
	cfg := monitor.DefaultConfig()
	flag.StringVar(&cfg.SourcesFile, "sources", cfg.SourcesFile, "text file containing Git repository URLs")
	flag.StringVar(&cfg.Workspace, "workspace", cfg.Workspace, "local cache directory for source repositories")
	flag.StringVar(&cfg.CompatibleDir, "compatible-dir", cfg.CompatibleDir, "output directory for Nuclei-compatible templates")
	flag.StringVar(&cfg.IncompatibleDir, "incompatible-dir", cfg.IncompatibleDir, "output directory for templates rejected by validation")
	flag.StringVar(&cfg.MetadataDir, "metadata-dir", cfg.MetadataDir, "output directory for manifests and reports")
	flag.StringVar(&cfg.NucleiBin, "nuclei", cfg.NucleiBin, "Nuclei executable path")
	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "number of concurrent validation workers")
	flag.IntVar(&cfg.Limit, "limit", cfg.Limit, "maximum templates to process per run; 0 means unlimited")
	flag.DurationVar(&cfg.CommandTimeout, "timeout", cfg.CommandTimeout, "timeout for each git or Nuclei command")
	flag.BoolVar(&cfg.CleanOutput, "clean-output", cfg.CleanOutput, "remove generated output directories before writing")
	flag.Parse()

	if cfg.Workers < 1 {
		log.Fatal(gerror.New("workers must be greater than zero"))
	}
	if cfg.Limit < 0 {
		log.Fatal(gerror.New("limit cannot be negative"))
	}

	ctx := context.Background()
	if err := monitor.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
