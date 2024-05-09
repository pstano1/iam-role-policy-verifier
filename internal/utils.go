// Package `utils` contains helper functions & models used in CLI
package utils

import (
	"encoding/json"

	"github.com/pstano1/iam-role-policy-verifier/pkg"
	"gopkg.in/yaml.v2"
)

// If file type is supported UnmarshalFile unmarshals file into `T` type struct
// & returns variable of given type otherwise returns an error
func UnmarshalFile[T any](fileContents []byte, fileFormat string) (T, error) {
	var bind T
	var err error
	switch fileFormat {
	case "json":
		err = json.Unmarshal(fileContents, &bind)
	case "yaml":
		err = yaml.Unmarshal(fileContents, &bind)
	default:
		return bind, pkg.ErrUnsupportedFileFormat
	}

	return bind, err
}
