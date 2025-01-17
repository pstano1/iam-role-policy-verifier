// Package `pkg` contains models & constants used throughout the project
package pkg

// This set of structs represent an AWS::IAM::Role Policy. For detailed documentation, please refer to:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-role-policy.html
type Statement struct {
	Sid      string   `yaml:"Sid"`
	Effect   string   `yaml:"Effect"`
	Action   []string `yaml:"Action"`
	Resource string   `yaml:"Resource"`
}

type PolicyDocument struct {
	Version   string      `yaml:"Version"`
	Statement []Statement `yaml:"Statement"`
}

type IAMRolePolicy struct {
	PolicyName     string         `yaml:"PolicyName"`
	PolicyDocument PolicyDocument `yaml:"PolicyDocument"`
}

// It returns an error if policy is malformed
func (p *IAMRolePolicy) IsValidIAMRolePolicy() error {
	if p.PolicyName == "" {
		return ErrMalformedPolicyObject
	}
	if p.PolicyDocument.Version == "" {
		return ErrMalformedPolicyObject
	}
	if len(p.PolicyDocument.Statement) == 0 {
		return ErrMalformedPolicyObject
	}
	for _, statement := range p.PolicyDocument.Statement {
		if statement.Effect == "" {
			return ErrMalformedPolicyObject
		}
		if len(statement.Action) == 0 {
			return ErrMalformedPolicyObject
		}
		if statement.Resource == "" {
			return ErrMalformedPolicyObject
		}
	}
	return nil
}
