package tlsconfig

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	// opa "github.com/open-policy-agent/opa/config"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// OPAAuthorize adapts any spiffeid.Matcher for use as an Authorizer which
// only authorizes the SPIFFE ID but otherwise ignores the verified chains.
func OPAAuthorize(config []byte) tlsconfig.Authorizer {
	return tlsconfig.Authorizer(func(actual spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		ctx := context.Background()

		opa, err := sdk.New(ctx, sdk.Options{
			ID:     "spiffe-opa-authorizer",
			Config: bytes.NewReader(config),
		})
		if err != nil {
			return errors.Join(err, fmt.Errorf("Failed to create OPA SDK"))
		}

		defer opa.Stop(ctx)

		// get the named policy decision for the specified input
		if result, err := opa.Decision(ctx, sdk.DecisionOptions{Path: "/authz/allow", Input: map[string]interface{}{"svc_spiffe_id": actual}}); err != nil {
			// handle error.
			return errors.Join(err, fmt.Errorf("Failed to get OPA policy decision"))
		} else if decision, ok := result.Result.(bool); !ok || !decision {
			// handle error.
			return errors.Join(err, fmt.Errorf("OPA policy decision failed"))
		}

		return nil
	})
}
