package monitor

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"
)

func sourceRevision(parent context.Context, source Source, timeout time.Duration) (string, error) {
	output, err := runCommandOutput(parent, timeout, "", "git", "ls-remote", source.URL, "HEAD")
	if err != nil {
		return "", gerror.Wrapf(err, "read revision for source %q", source.URL)
	}
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return "", gerror.Newf("source %q returned no HEAD revision", source.URL)
	}
	return fields[0], nil
}

func readSources(path string) ([]Source, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, gerror.Wrapf(err, "open sources file %q", path)
	}
	defer file.Close()

	seen := make(map[string]struct{})
	var sources []Source
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, gerror.Newf("invalid source URL %q", line)
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		sources = append(sources, Source{URL: line, Name: sourceName(parsed.Path)})
	}
	if err := scanner.Err(); err != nil {
		return nil, gerror.Wrap(err, "read sources file")
	}
	if len(sources) == 0 {
		return nil, gerror.Newf("sources file %q contains no repositories", path)
	}
	return sources, nil
}

func sourceName(path string) string {
	trimmed := strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	parts := strings.Split(trimmed, "/")
	if len(parts) >= 2 {
		return safeName(parts[len(parts)-2] + "__" + parts[len(parts)-1])
	}
	return safeName(trimmed)
}

func syncSource(parent context.Context, source Source, workspace string, timeout time.Duration) (string, error) {
	target := filepath.Join(workspace, source.Name)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return "", gerror.Wrapf(err, "create source workspace %q", workspace)
	}
	if _, err := os.Stat(filepath.Join(target, ".git")); err == nil {
		if err := runCommand(parent, timeout, workspace, "git", "-C", target, "pull", "--ff-only", "--depth=1"); err != nil {
			return "", gerror.Wrapf(err, "update source %q", source.URL)
		}
		return target, nil
	}
	if _, err := os.Stat(target); err == nil {
		if err := os.RemoveAll(target); err != nil {
			return "", gerror.Wrapf(err, "remove incomplete source checkout %q", target)
		}
	}
	if err := runCommand(parent, timeout, workspace, "git", "clone", "--depth", "1", "--single-branch", "--no-tags", source.URL, target); err != nil {
		return "", gerror.Wrapf(err, "clone source %q", source.URL)
	}
	return target, nil
}

func runCommand(parent context.Context, timeout time.Duration, dir string, name string, args ...string) error {
	_, err := runCommandOutput(parent, timeout, dir, name, args...)
	return err
}

func runCommandOutput(parent context.Context, timeout time.Duration, dir string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return "", gerror.Newf("%s %s: %s", name, strings.Join(args, " "), truncate(message, 800))
	}
	return string(output), nil
}

func safeName(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
