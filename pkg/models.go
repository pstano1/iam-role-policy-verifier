package pkg

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
