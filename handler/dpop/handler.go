package dpop

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

type Handler struct {
	// If set to true, clients must use PKCE.
	Force bool

	DPoPStrategy fosite.DPoPStrategy
}

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if request.GetDpopProofJWT() == "" {
		if c.Force {
			return errorsx.WithStack(fosite.ErrInvalidRequest.
				WithHint("Clients must include a dpop proof jwt when performing the token reqeust, but it is missing."))
		}
		return nil
	}

	dpjwt, err := c.DPoPStrategy.VerifyDPoP(ctx, request.GetDpopProofJWT())
	if err != nil {
		return err
	}

	request.SetJKT(dpjwt.JWKThumbprint)
	return nil
}

// AT発行後にPoPを呼ぶ？
// AccessTokenHashを追加する必要もある
