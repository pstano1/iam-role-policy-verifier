package policyverifier

import (
	"github.com/pstano1/iam-role-policy-verifier/pkg"
	"github.com/sirupsen/logrus"
)

type IPolicyVerifier interface {
	Verify(policy pkg.IAMRolePolicy) (bool, error)
}

type PolicyVerifier struct {
	log logrus.FieldLogger
}

func NewPolicyVerifier(logger logrus.FieldLogger) IPolicyVerifier {
	return &PolicyVerifier{
		log: logger,
	}
}

func (p *PolicyVerifier) Verify(policy pkg.IAMRolePolicy) (bool, error) {
	p.log.Debugf("starting verification for %s", policy.PolicyName)
	if err := policy.IsValidIAMRolePolicy(); err != nil {
		return false, err
	}
	for _, statement := range policy.PolicyDocument.Statement {
		if statement.Resource == "*" {
			return false, nil
		}
	}
	return true, nil
}
