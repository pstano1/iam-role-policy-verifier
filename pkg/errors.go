// Package `pkg` contains models & constants used throughout the project
package pkg

import "errors"

// Set of standardized errors used throughout the project
var (
	ErrFilePathNotSpecified  = errors.New("file path must be specified")
	ErrReadingFile           = errors.New("error while reading specified file")
	ErrDecodingFile          = errors.New("error while unmarshaling file")
	ErrMalformedPolicyObject = errors.New("malformed policy object")
	ErrUnsupportedFileFormat = errors.New("usupported file format")
)
