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

	flags := parseFlags()
	if !flags.IsFilePath() {
		logger.Fatal(pkg.ErrFilePathNotSpecified)
		return
	}
	fileContents, err := readFile(flags.FilePath, logger)
	if err != nil {
		logger.Fatal(err)
		return
	}

	policies, err := unmarshalFile[pkg.IAMRolePolicy](fileContents, *flags.FileFormat, flags.IsBatchFile(), logger)
	if err != nil {
		logger.Fatal(err)
		return
	}
	for _, policy := range policies {
		proccessPolicy(verifier, policy, logger)
	}
}

func proccessPolicy(verifier policyverifier.IPolicyVerifier, policy pkg.IAMRolePolicy, logger logrus.FieldLogger) {
	ok, err := verifier.CheckForResourceWildcard(policy)
	if err != nil {
		logger.Error(err)
		return
	}
	logger.Infof("policy %s returned %t", policy.PolicyName, ok)
}

func unmarshalFile[T any](fileContents []byte, fileFormat string, batch bool, logger logrus.FieldLogger) ([]T, error) {
	var err error

	if batch {
		bind, err := utils.UnmarshalFile[[]T](fileContents, fileFormat)
		return bind, err
	}

	bind, err := utils.UnmarshalFile[T](fileContents, fileFormat)

	return []T{bind}, err
}

func readFile(filePath *string, logger logrus.FieldLogger) ([]byte, error) {
	var fileContents []byte
	var err error

	file, err := os.Open(*filePath)
	if err != nil {
		logger.Fatal(err)
		return fileContents, err
	}
	defer file.Close()
	fileContents, err = io.ReadAll(file)
	if err != nil {
		logger.Fatalf("%v: %s", pkg.ErrReadingFile, err)
		return fileContents, pkg.ErrReadingFile
	}
	return fileContents, err
}

func parseFlags() utils.CLIFlags {
	var flags utils.CLIFlags

	flags.FilePath = flag.String("file", "", "file to be checked path")
	flags.Batch = flag.Bool("batch", false, "specify if batched check")
	flags.FileFormat = flag.String("format", "json", "format of file to be checked")
	flag.Parse()

	return flags
}
