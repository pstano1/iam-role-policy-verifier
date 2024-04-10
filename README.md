# IAM Role Policy Verifier

IAM Role Policy Verifier is a Go package that provides functionalities to verify the correctness of AWS IAM role policies. It checks for `Resource` field if it contains doesn't contain a wildcard.

## Installation

To install CLI tool make sure you have Go installed on your system then follow instructions below:

```console
go install github.com/pstano1/iam-role-policy-verifier/cmd/main
```

To use within own project:

```console
go get github.com/pstano1/iam-role-policy-verifier/pkg
```

## Usage

#### using CLI

Possible flags:

|flag|data type|requirement|description|
|--------|--------|--------|--------|
|file|string|required|path to file containing policies to check|
|batch| - |optional|allows to check files containg more than one policy|

```console
iam-policy-verifier --file ./resource.json
```

#### using in project


```go
import (
    "github.com/pstano1/iam-role-policy-verifier/pkg"
    policyverifier "github.com/pstano1/iam-role-policy-verifier/pkg/policyverifier"
)

logger := logrus.New()
verifier := policyverifier.NewPolicyVerifier(logger.WithField("component", "policyVerifier"))

policy := pkg.IAMRolePolicy{
	PolicyName: "example-policy",
	PolicyDocument: pkg.PolicyDocument{
        Version: "2012-10-17",
		Statement: []pkg.Statement{
			{
                Sid:      "ExampleSid",
				Effect:   "Allow",
				Action:   []string{"s3:GetObject"},
				Resource: "arn:aws:s3:::example-bucket/*",
			},
		},
	},
}

ok, err := verifier.CheckForResourceWildcard(policy)
if err != nil {
	logger.Error(err)
}
print(ok)
```