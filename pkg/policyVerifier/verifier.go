package policyverifier

import (
	"github.com/pstano1/iam-role-policy-verifier/pkg"
	"github.com/sirupsen/logrus"
)

type IPolicyVerifier interface {
	CheckForResourceWildcard(policy pkg.IAMRolePolicy) (bool, error)
}

type PolicyVerifier struct {
	log logrus.FieldLogger
}

// NewPolicyVerifier creates a new PolicyVerifier instance
func NewPolicyVerifier(logger logrus.FieldLogger) IPolicyVerifier {
	return &PolicyVerifier{
		log: logger,
	}
}

// CheckForResourceWildcard checks if the given AWS::IAM::Role Policy contains wildcard resources.
// It returns true if no wildcard resource is found, otherwise false.
func (p *PolicyVerifier) CheckForResourceWildcard(policy pkg.IAMRolePolicy) (bool, error) {
	p.log.Debugf("starting verification for %s", policy.PolicyName)

	// Check if policy's body isn't malformed
	if err := policy.IsValidIAMRolePolicy(); err != nil {
		return false, err
	}

	// Check if `Resource` field contains wildcard
	for _, statement := range policy.PolicyDocument.Statement {
		if statement.Resource == "*" {
			return false, nil
		}
	}
	return true, nil
}
