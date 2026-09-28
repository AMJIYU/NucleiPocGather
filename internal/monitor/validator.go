package monitor

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
)

func validateWithNuclei(parent context.Context, cfg Config, path string) error {
	failed, err := validateBatchWithNuclei(parent, cfg, []string{path})
	if err != nil {
		return err
	}
	if failed {
		return gerror.New("nuclei validation failed")
	}
	return nil
}

func validateBatchWithNuclei(parent context.Context, cfg Config, paths []string) (bool, error) {
	if len(paths) == 0 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(parent, cfg.CommandTimeout)
	defer cancel()
	args := []string{"-validate", "-silent", "-no-color"}
	for _, path := range paths {
		args = append(args, "-t", path)
	}
	cmd := exec.CommandContext(ctx, cfg.NucleiBin, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return false, nil
	}
	if ctx.Err() != nil {
		return false, gerror.Wrap(ctx.Err(), "nuclei validation command cancelled")
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return false, gerror.Wrap(err, "run nuclei validation")
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	return true, gerror.Newf("nuclei validation failed: %s", truncate(message, 800))
}
