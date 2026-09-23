package monitor

import (
	"context"
	"os/exec"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
)

func validateWithNuclei(parent context.Context, cfg Config, path string) error {
	ctx, cancel := context.WithTimeout(parent, cfg.CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cfg.NucleiBin, "-validate", "-t", path, "-silent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return gerror.Newf("nuclei validation failed: %s", truncate(message, 800))
	}
	return nil
}
