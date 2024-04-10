package tests

import (
	"errors"
	"testing"

	"github.com/pstano1/iam-role-policy-verifier/pkg"
	policyverifier "github.com/pstano1/iam-role-policy-verifier/pkg/policyVerifier"
	"github.com/sirupsen/logrus"
)

var (
	p      policyverifier.IPolicyVerifier
	logger *logrus.Logger
)

func init() {
	logger = logrus.New()
}

func TestMain(m *testing.M) {
	p = policyverifier.NewPolicyVerifier(logger)

	m.Run()
}

type VerifyReturnValue struct {
	ok  bool
	err error
}

func TestVerifyFunc(t *testing.T) {
	var tests = []struct {
		name   string
		policy pkg.IAMRolePolicy
		want   VerifyReturnValue
	}{
		{
			name: "AWS docs example",
			policy: pkg.IAMRolePolicy{
				PolicyName: "root",
				PolicyDocument: pkg.PolicyDocument{
					Version: "2012-10-17",
					Statement: []pkg.Statement{
						{
							Sid:      "IamListAccess",
							Effect:   "Allow",
							Action:   []string{"iam:ListRoles", "iam:ListUsers"},
							Resource: "*",
						},
					},
				},
			},
			want: VerifyReturnValue{
				ok:  false,
				err: nil,
			},
		},
		{
			name: "empty PolicyName",
			policy: pkg.IAMRolePolicy{
				PolicyName: "",
				PolicyDocument: pkg.PolicyDocument{
					Version: "2012-10-17",
					Statement: []pkg.Statement{
						{
							Sid:      "IamListAccess",
							Effect:   "Allow",
							Action:   []string{"iam:ListRoles", "iam:ListUsers"},
							Resource: "*",
						},
					},
				},
			},
			want: VerifyReturnValue{
				ok:  false,
				err: pkg.ErrMalformedPolicyObject,
			},
		},
		{
			name: "empty Version",
			policy: pkg.IAMRolePolicy{
				PolicyName: "root",
				PolicyDocument: pkg.PolicyDocument{
					Version: "",
					Statement: []pkg.Statement{
						{
							Sid:      "IamListAccess",
							Effect:   "Allow",
							Action:   []string{"iam:ListRoles", "iam:ListUsers"},
							Resource: "arn:aws:s3:::example-bucket/*",
						},
					},
				},
			},
			want: VerifyReturnValue{
				ok:  false,
				err: pkg.ErrMalformedPolicyObject,
			},
		},
		{
			name: "non single asterisk resource",
			policy: pkg.IAMRolePolicy{
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
			},
			want: VerifyReturnValue{
				ok:  true,
				err: nil,
			},
		},
		{
			name: "empty statement",
			policy: pkg.IAMRolePolicy{
				PolicyName: "example-policy",
				PolicyDocument: pkg.PolicyDocument{
					Version:   "2012-10-17",
					Statement: []pkg.Statement{},
				},
			},
			want: VerifyReturnValue{
				ok:  false,
				err: pkg.ErrMalformedPolicyObject,
			},
		},
		{
			name: "empty resource",
			policy: pkg.IAMRolePolicy{
				PolicyName: "example-policy",
				PolicyDocument: pkg.PolicyDocument{
					Version: "2012-10-17",
					Statement: []pkg.Statement{
						{
							Sid:      "ExampleSid",
							Effect:   "Allow",
							Action:   []string{"s3:GetObject"},
							Resource: "",
						},
					},
				},
			},
			want: VerifyReturnValue{
				ok:  false,
				err: pkg.ErrMalformedPolicyObject,
			},
		},
		{
			name: "empty PolicyDocument",
			policy: pkg.IAMRolePolicy{
				PolicyName:     "example-policy",
				PolicyDocument: pkg.PolicyDocument{},
			},
			want: VerifyReturnValue{
				ok:  false,
				err: pkg.ErrMalformedPolicyObject,
			},
		},
		{
			name: "multiple statements",
			policy: pkg.IAMRolePolicy{
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
						{
							Sid:      "ExampleSid",
							Effect:   "Allow",
							Action:   []string{"s3:GetObject"},
							Resource: "*",
						},
					},
				},
			},
			want: VerifyReturnValue{
				ok:  false,
				err: nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ok, err := p.CheckForResourceWildcard(test.policy)
			if ok != test.want.ok {
				t.Errorf("got %t, want %t", ok, test.want.ok)
			}
			if !errors.Is(err, test.want.err) {
				t.Errorf("got %v, want %v", err, test.want.err)
			}
		})
	}
}
