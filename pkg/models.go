package pkg

type Statement struct {
	Sid      string
	Effect   string
	Action   []string
	Resource string
}

type PolicyDocument struct {
	Version   string
	Statement []Statement
}

type IAMRolePolicy struct {
	PolicyName     string
	PolicyDocument PolicyDocument
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
