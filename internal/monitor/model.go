package monitor

import "time"

type Source struct {
	URL  string
	Name string
}

type SourceState struct {
	URL       string    `json:"url"`
	Name      string    `json:"name"`
	Revision  string    `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TemplateMeta struct {
	ID       string
	Name     string
	Severity string
	Tags     []string
	Protocol string
}

type Record struct {
	Source       string    `json:"source"`
	SourceURL    string    `json:"source_url"`
	RelativePath string    `json:"relative_path"`
	ID           string    `json:"id,omitempty"`
	Name         string    `json:"name,omitempty"`
	Severity     string    `json:"severity,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	Protocol     string    `json:"protocol,omitempty"`
	Status       string    `json:"status"`
	Reason       string    `json:"reason,omitempty"`
	Message      string    `json:"message,omitempty"`
	Categories   []string  `json:"categories,omitempty"`
	OutputPaths  []string  `json:"output_paths,omitempty"`
	SHA256       string    `json:"sha256"`
	ProcessedAt  time.Time `json:"processed_at"`
}

type Summary struct {
	GeneratedAt    time.Time      `json:"generated_at"`
	Total          int            `json:"total"`
	Compatible     int            `json:"compatible"`
	Incompatible   int            `json:"incompatible"`
	Duplicates     int            `json:"duplicates"`
	Categories     map[string]int `json:"categories"`
	IncompatibleBy map[string]int `json:"incompatible_by_reason"`
	Severities     map[string]int `json:"severities"`
}

type evaluated struct {
	Path   string
	Source Source
	Meta   TemplateMeta
	Hash   string
	Record Record
}
