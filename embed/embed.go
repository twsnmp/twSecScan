package embed

import (
	"embed"
	"strings"
)

//go:embed wordlists/*.txt
var wordlistsFS embed.FS

// GetSubdomainWordlist returns the subdomains list as a slice of strings.
func GetSubdomainWordlist() ([]string, error) {
	data, err := wordlistsFS.ReadFile("wordlists/subdomains.txt")
	if err != nil {
		return nil, err
	}
	return parseLines(string(data)), nil
}

// GetDirectoryWordlist returns the directories list as a slice of strings.
func GetDirectoryWordlist() ([]string, error) {
	data, err := wordlistsFS.ReadFile("wordlists/directories.txt")
	if err != nil {
		return nil, err
	}
	return parseLines(string(data)), nil
}

func parseLines(content string) []string {
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			result = append(result, trimmed)
		}
	}
	return result
}
