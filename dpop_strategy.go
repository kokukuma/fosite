package fosite

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const dpopHeaderName = "DPoP"

type DpopProofJWT struct {
	JID             string `json:"jti"`
	HTTPMethod      string `json:"htm"`
	HTTPEndpoint    string `json:"htu"`
	IssuedAt        int64  `json:"iat"`
	AccessTokenHash string `json:"ath"`

	JWKThumbprint string
}

type DPoPStrategy interface {
	VerifyDPoP(ctx context.Context, dpopProofJWT string) (dpjwt *DpopProofJWT, err error)
}

type DefaultDpopStrategy struct{}

func (f *DefaultDpopStrategy) VerifyDPoP(ctx context.Context, dpJWT string) (*DpopProofJWT, error) {
	parsed, err := jwt.ParseSigned(dpJWT)
	if err != nil {
		return nil, err
	}
	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("invalid token: expected only 1 signature")
	}
	key, err := getJwkKey(parsed.Headers[0])
	if err != nil {
		return nil, err
	}
	dpjwtClaims := &DpopProofJWT{}
	if err := parsed.Claims(key.Public().Key, dpjwtClaims); err != nil {
		return nil, err
	}

	if dpjwtClaims.IssuedAt > time.Now().Unix() {
		return nil, fmt.Errorf("invalid issuedAt")
	}

	if getTyp(parsed.Headers[0]) != "dpop+jwt" {
		return nil, fmt.Errorf("invalid typ")
	}

	t, err := jwkThumbprint(*key)
	if err != nil {
		return nil, err
	}
	dpjwtClaims.JWKThumbprint = t

	return dpjwtClaims, nil
}

func NewDefaultDpopStrategy() *DefaultDpopStrategy {
	return &DefaultDpopStrategy{}
}

func getDPoPHeader(header http.Header) (string, bool) {
	if _, ok := header[http.CanonicalHeaderKey(dpopHeaderName)]; !ok {
		return "", false
	}

	return header.Get(dpopHeaderName), true
}

func getTyp(header jose.Header) string {
	typ, ok := header.ExtraHeaders[jose.HeaderType]
	if !ok {
		return ""
	}
	if s, ok := typ.(string); ok {
		return s
	}
	return ""
}

func getJwkKey(header jose.Header) (*jose.JSONWebKey, error) {
	jwk := header.JSONWebKey
	if jwk == nil {
		return nil, errors.New("missing JWK")
	}

	if !jwk.Valid() {
		return jwk, errors.New("failed JWK validation")
	}

	if !jwk.IsPublic() {
		return jwk, errors.New("client assertion JWK should be a public key")
	}

	return jwk, nil
}

func jwkThumbprint(jwk jose.JSONWebKey) (string, error) {
	thumbp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbp), nil
}
