package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/pstano1/iam-role-policy-verifier/pkg"
	policyverifier "github.com/pstano1/iam-role-policy-verifier/pkg/policyVerifier"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	verifier := policyverifier.NewPolicyVerifier(logger.WithField("component", "verifier"))

	filePath := flag.String("file", "", "file to be checked path")
	batch := flag.Bool("batch", false, "specify if batched check")

	flag.Parse()
	if *filePath == "" {
		logger.Fatal("file path must be specified")
	}
	file, err := os.Open(*filePath)
	if err != nil {
		logger.Fatal(err)
		return
	}
	defer file.Close()
	jsonData, err := io.ReadAll(file)
	if err != nil {
		logger.Fatalf("error reading JSON file: %s", err)
		return
	}
	if *batch {
		var policies []pkg.IAMRolePolicy
		err = json.Unmarshal(jsonData, &policies)
		if err != nil {
			logger.Fatalf("error decoding JSON: %s", err)
			return
		}
		for _, policy := range policies {
			isValid, err := verifier.Verify(policy)
			if err != nil {
				logger.Error(err)
			}
			logger.Infof("asked policy is %t", isValid)
		}
	} else {
		var policy pkg.IAMRolePolicy
		err = json.Unmarshal(jsonData, &policy)
		if err != nil {
			logger.Fatalf("error decoding JSON: %s", err)
			return
		}
		isValid, err := verifier.Verify(policy)
		if err != nil {
			logger.Error(err)
		}
		logger.Infof("asked policy is %t", isValid)
	}
}
