package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/pstano1/iam-role-policy-verifier/pkg"
	policyverifier "github.com/pstano1/iam-role-policy-verifier/pkg/policyVerifier"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func main() {
	logger := logrus.New()
	verifier := policyverifier.NewPolicyVerifier(logger.WithField("component", "policyVerifier"))

	filePath := flag.String("file", "", "file to be checked path")
	batch := flag.Bool("batch", false, "specify if batched check")
	fileFormat := flag.String("format", "json", "format of file to be checked")

	flag.Parse()
	if *filePath == "" {
		logger.Fatal(pkg.ErrFilePathNotSpecified)
	}
	file, err := os.Open(*filePath)
	if err != nil {
		logger.Fatal(err)
		return
	}
	defer file.Close()
	fileContents, err := io.ReadAll(file)
	if err != nil {
		logger.Fatalf("%v: %s", pkg.ErrReadingFile, err)
		return
	}
	if *batch {
		policies, err := unmarshalFile[[]pkg.IAMRolePolicy](fileContents, *fileFormat)
		if err != err {
			logger.Fatalf("%s: %s", pkg.ErrDecodingFile, err)
		}
		for _, policy := range policies {
			ok, err := verifier.CheckForResourceWildcard(policy)
			if err != nil {
				logger.Error(err)
				continue
			}
			logger.Infof("policy %s returned %t", policy.PolicyName, ok)
		}
	} else {
		policy, err := unmarshalFile[pkg.IAMRolePolicy](fileContents, *fileFormat)
		if err != err {
			logger.Fatalf("%s: %s", pkg.ErrDecodingFile, err)
		}
		ok, err := verifier.CheckForResourceWildcard(policy)
		if err != nil {
			logger.Error(err)
			return
		}
		logger.Infof("policy %s returned %t", policy.PolicyName, ok)
	}
}

func unmarshalFile[T any](fileContents []byte, fileFormat string) (T, error) {
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
