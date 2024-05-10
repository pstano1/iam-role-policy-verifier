// Package `utils` contains helper functions & models used in CLI
package utils

type CLIFlags struct {
	FilePath   *string
	Batch      *bool
	FileFormat *string
}

func (c *CLIFlags) IsFilePath() bool {
	return *c.FilePath != ""
}

func (c *CLIFlags) IsBatchFile() bool {
	return *c.Batch
}
