package transform

import (
	"fmt"
	"os"

	"github.com/xenolf/lego/acme"
)

type DNSProvider struct {
	Domain string
	Inner  acme.ChallengeProvider
}

// NewDNSProvider creates a provider that simply wraps another provider, transforming the domain that it acts on.
// This lets you use a dedicated validation domain without needing to directly modify the domains you are issuing certs for.
// Usage (In this example we will validate example.com via exvalidate.com):
// 1. Select a validation domain. Set it in the TRANSFORM_DOMAIN env var.
// 2. Set a CNAME on your target domains so that _acme-challenge.example.com points to _acme-challenge.example.com.exvalidate.com
// 3. Set TRANSFORM_PROVIDER to the actual dns provider validation type (route53, gcloud, etc..) to manage exvalidate.com
// 4. Set up other environment variable credentials as needed by the inner provider
//
// This function accepts a function argument only because directly calling dns.NewDNSChallengeProviderByName would create an import loop
func NewDNSProvider(initer func(name string) (acme.ChallengeProvider, error)) (acme.ChallengeProvider, error) {
	innerType := os.Getenv("TRANSFORM_PROVIDER")
	domain := os.Getenv("TRANSFORM_DOMAIN")
	if innerType == "" || innerType == "transform" || domain == "" {
		return nil, fmt.Errorf("Transform provider requires TRANSFORM_PROVIDER and TRANSFORM_DOMAIN environment variables")
	}
	inner, err := initer(innerType)
	if err != nil {
		return nil, err
	}
	return &DNSProvider{
		Inner:  inner,
		Domain: domain,
	}, nil
}

func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	return c.Inner.Present(fmt.Sprintf("%s.%s", domain, c.Domain), token, keyAuth)
}

func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	return c.Inner.CleanUp(fmt.Sprintf("%s.%s", domain, c.Domain), token, keyAuth)
}
