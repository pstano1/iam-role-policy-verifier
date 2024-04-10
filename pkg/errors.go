package pkg

import "errors"

var (
	ErrFilePathNotSpecified  = errors.New("file path must be specified")
	ErrReadingFile           = errors.New("error while reading specified file")
	ErrDecodingFile          = errors.New("error while unmarshaling file")
	ErrMalformedPolicyObject = errors.New("malformed policy object")
	ErrUnsupportedFileFormat = errors.New("usupported file format")
)
