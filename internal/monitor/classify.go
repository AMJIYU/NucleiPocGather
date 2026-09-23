package monitor

import "strings"

type categoryRule struct {
	Name     string
	Keywords []string
}

var categoryRules = []categoryRule{
	{Name: "cve", Keywords: []string{"cve-", "cve20", "cve19"}},
	{Name: "cnvd", Keywords: []string{"cnvd"}},
	{Name: "wordpress", Keywords: []string{"wordpress", "wp-", "wp_"}},
	{Name: "xss", Keywords: []string{"xss", "cross-site-scripting"}},
	{Name: "sqli", Keywords: []string{"sqli", "sql-injection", "sql_injection"}},
	{Name: "ssrf", Keywords: []string{"ssrf", "server-side-request-forgery"}},
	{Name: "rce", Keywords: []string{"rce", "remote-code-execution", "command-injection"}},
	{Name: "lfi", Keywords: []string{"lfi", "local-file-inclusion", "path-traversal", "directory-traversal"}},
	{Name: "xxe", Keywords: []string{"xxe", "xml-external-entity"}},
	{Name: "auth", Keywords: []string{"auth", "login", "oauth", "sso", "jwt", "credential", "password"}},
	{Name: "exposure", Keywords: []string{"expos", "disclosure", "leak", "sensitive", "misconfig"}},
	{Name: "upload", Keywords: []string{"upload", "file-upload"}},
	{Name: "api", Keywords: []string{"api", "graphql", "swagger"}},
	{Name: "cloud", Keywords: []string{"aws", "azure", "gcp", "cloud", "s3", "ec2"}},
	{Name: "container", Keywords: []string{"docker", "kubernetes", "container"}},
	{Name: "java", Keywords: []string{"java", "spring", "struts", "tomcat", "weblogic", "jenkins"}},
	{Name: "microsoft", Keywords: []string{"microsoft", "exchange", "sharepoint", "iis", "windows"}},
	{Name: "network", Keywords: []string{"dns", "ftp", "ssh", "smtp", "ldap", "tcp", "udp", "network"}},
	{Name: "detect", Keywords: []string{"detect", "fingerprint", "version"}},
	{Name: "fuzz", Keywords: []string{"fuzz", "fuzzing"}},
}

func categoriesFor(path string, meta TemplateMeta) []string {
	text := strings.ToLower(strings.Join([]string{path, meta.ID, meta.Name, strings.Join(meta.Tags, " ")}, " "))
	categories := make([]string, 0, 3)
	for _, rule := range categoryRules {
		for _, keyword := range rule.Keywords {
			if strings.Contains(text, keyword) {
				categories = append(categories, rule.Name)
				break
			}
		}
	}
	if len(categories) == 0 {
		return []string{"other"}
	}
	return categories
}
