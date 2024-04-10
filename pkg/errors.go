package pkg

import "errors"

var (
	ErrFilePathNotSpecified  = errors.New("file path must be specified")
	ErrReadingFile           = errors.New("error while reading specified file")
	ErrDecodingJSON          = errors.New("error while unmarshaling JSON file")
	ErrMalformedPolicyObject = errors.New("malformed policy object")
)
