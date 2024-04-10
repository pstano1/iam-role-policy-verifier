package main

import (
	"flag"
	"io"
	"os"

	utils "github.com/pstano1/iam-role-policy-verifier/internal"
	"github.com/pstano1/iam-role-policy-verifier/pkg"
	policyverifier "github.com/pstano1/iam-role-policy-verifier/pkg/policyVerifier"
	"github.com/sirupsen/logrus"
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
		policies, err := utils.UnmarshalFile[[]pkg.IAMRolePolicy](fileContents, *fileFormat)
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
		policy, err := utils.UnmarshalFile[pkg.IAMRolePolicy](fileContents, *fileFormat)
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
