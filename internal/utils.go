package utils

import (
	"encoding/json"

	"github.com/pstano1/iam-role-policy-verifier/pkg"
	"gopkg.in/yaml.v2"
)

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
	if err != nil {
		return bind, err
	}

	return bind, nil
}
