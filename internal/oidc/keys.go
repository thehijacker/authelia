package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"
	"gopkg.in/square/go-jose.v2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// NewKeyManagerWithConfiguration when provided a schema.OpenIDConnectConfiguration creates a new KeyManager and adds an
// initial key to the manager.
func NewKeyManagerWithConfiguration(config *schema.OpenIDConnectConfiguration) (manager *KeyManager, err error) {
	manager = NewKeyManager()

	if _, err = manager.AddActiveJWK(config.IssuerCertificateChain, config.IssuerPrivateKey); err != nil {
		return nil, err
	}

	return manager, nil
}

// NewKeyManager creates a new empty KeyManager.
func NewKeyManager() (manager *KeyManager) {
	return &KeyManager{
		jwks: &jose.JSONWebKeySet{},
	}
}

// Strategy returns the fosite jwt.JWTStrategy.
func (m *KeyManager) Strategy() (strategy jwt.JWTStrategy) {
	if m.jwk == nil {
		return nil
	}

	return m.jwk.Strategy()
}

// GetKeySet returns the joseJSONWebKeySet containing the rsa.PublicKey types.
func (m *KeyManager) GetKeySet() (jwks *jose.JSONWebKeySet) {
	return m.jwks
}

// GetActiveJWK obtains the currently active jose.JSONWebKey.
func (m *KeyManager) GetActiveJWK() (jwk *jose.JSONWebKey, err error) {
	if m.jwks == nil || m.jwk == nil {
		return nil, errors.New("could not obtain the active JWK from an improperly configured key manager")
	}

	jwks := m.jwks.Key(m.jwk.id)

	if len(jwks) == 1 {
		return &jwks[0], nil
	}

	if len(jwks) == 0 {
		return nil, errors.New("could not find a key with the active key id")
	}

	return nil, errors.New("multiple keys with the same key id")
}

// GetActiveKeyID returns the key id of the currently active key.
func (m *KeyManager) GetActiveKeyID() (keyID string) {
	if m.jwk == nil {
		return ""
	}

	return m.jwk.id
}

// GetActivePrivateKey returns the rsa.PrivateKey of the currently active key.
func (m *KeyManager) GetActivePrivateKey() (key *rsa.PrivateKey, err error) {
	if m.jwk == nil {
		return nil, errors.New("failed to retrieve active private key")
	}

	return m.jwk.key, nil
}

// AddActiveJWK is used to add a cert and key pair.
func (m *KeyManager) AddActiveJWK(chain schema.X509CertificateChain, key *rsa.PrivateKey) (jwk *JWK, err error) {
	// TODO: Add a mutex when implementing key rotation to be utilized here and in methods which retrieve the JWK or JWKS.
	if m.jwk, err = NewJWK(chain, key); err != nil {
		return nil, err
	}

	m.jwks.Keys = append(m.jwks.Keys, *m.jwk.JSONWebKey())

	return m.jwk, nil
}

// JWTStrategy is a decorator struct for the fosite jwt.JWTStrategy.
type JWTStrategy struct {
	jwt.JWTStrategy

	id string
}

// KeyID returns the key id.
func (s *JWTStrategy) KeyID() (id string) {
	return s.id
}

// GetPublicKeyID is a decorator func for the underlying fosite RS256JWTStrategy.
func (s *JWTStrategy) GetPublicKeyID(_ context.Context) (string, error) {
	return s.id, nil
}

// NewJWK creates a new JWK.
func NewJWK(chain schema.X509CertificateChain, key *rsa.PrivateKey) (j *JWK, err error) {
	if key == nil {
		return nil, fmt.Errorf("JWK is not properly initialized: missing key")
	}

	j = &JWK{
		key:   key,
		chain: chain,
	}

	jwk := &jose.JSONWebKey{
		Algorithm: "RS256",
		Use:       "sig",
		Key:       &key.PublicKey,
	}

	var thumbprint []byte

	if thumbprint, err = jwk.Thumbprint(crypto.SHA1); err != nil {
		return nil, fmt.Errorf("failed to calculate SHA1 thumbprint for certificate: %w", err)
	}

	j.id = strings.ToLower(fmt.Sprintf("%x", thumbprint))

	if len(j.id) >= 7 {
		j.id = j.id[:6]
	}

	if len(j.id) >= 7 {
		j.id = j.id[:6]
	}

	return j, nil
}

// JWK is a utility wrapper for JSON Web Key's.
type JWK struct {
	id    string
	key   *rsa.PrivateKey
	chain schema.X509CertificateChain
}

// Strategy returns the relevant jwt.JWTStrategy for this JWT.
func (j *JWK) Strategy() (strategy jwt.JWTStrategy) {
	return &JWTStrategy{id: j.id, JWTStrategy: &RS256JWTStrategy{PrivateKey: j.key}}
}

// JSONWebKey returns the relevant *jose.JSONWebKey for this JWT.
func (j *JWK) JSONWebKey() (jwk *jose.JSONWebKey) {
	jwk = &jose.JSONWebKey{
		Key:          &j.key.PublicKey,
		KeyID:        j.id,
		Algorithm:    "RS256",
		Use:          "sig",
		Certificates: j.chain.Certificates(),
	}

	if len(jwk.Certificates) != 0 {
		jwk.CertificateThumbprintSHA1, jwk.CertificateThumbprintSHA256 = j.chain.Thumbprint(crypto.SHA1), j.chain.Thumbprint(crypto.SHA256)
	}

	return jwk
}

// RS256JWTStrategy is responsible for generating and validating JWT challenges
type RS256JWTStrategy struct {
	*rsa.PrivateKey
}

// Generate generates a new authorize code or returns an error. set secret
func (j *RS256JWTStrategy) Generate(ctx context.Context, claims jwt.MapClaims, header jwt.Mapper) (rawToken, sig string, err error) {
	rawToken, sig, err = generateToken(claims, header, jose.RS256, j.PrivateKey)

	fmt.Printf("----- Generate(ctx: %+v, claims: %+v, header: %+v) -> (rawToken: %s, sig: %s, err: %+v\n", ctx, claims, header, rawToken, sig, err)

	return
}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (j *RS256JWTStrategy) Validate(ctx context.Context, token string) (sig string, err error) {
	sig, err = validateToken(token, j.PublicKey)

	fmt.Printf("----- Validate(ctx: %+v, token: %+v) -> (sig: %s, err: %+v)\n", ctx, token, sig, err)

	return
}

// Decode will decode a JWT token
func (j *RS256JWTStrategy) Decode(ctx context.Context, rawToken string) (token *jwt.Token, err error) {
	token, err = decodeToken(rawToken, j.PublicKey)

	fmt.Printf("----- Decode(ctx: %+v, rawToken: %s) -> (token: %+v, err: %+v)\n", ctx, rawToken, token, err)

	return
}

// GetSignature will return the signature of a token
func (j *RS256JWTStrategy) GetSignature(ctx context.Context, token string) (sig string, err error) {
	sig, err = getTokenSignature(token)

	fmt.Printf("----- GetSignature(ctx: %+v, token: %+v) -> (sig: %s, err: %+v)\n", ctx, token, sig, err)

	return
}

// Hash will return a given hash based on the byte input or an error upon fail
func (j *RS256JWTStrategy) Hash(ctx context.Context, in []byte) (out []byte, err error) {
	out, err = hashSHA256(in)

	fmt.Printf("----- Hash(ctx: %+v, in: %s) -> (out: %s, err: %+v)\n", ctx, in, out, err)

	return
}

// GetSigningMethodLength will return the length of the signing method
func (j *RS256JWTStrategy) GetSigningMethodLength() int {

	fmt.Printf("----- GetSigningMethodLength() -> (size: %d)\n", crypto.SHA256.Size())

	return crypto.SHA256.Size()
}

func getTokenSignature(token string) (string, error) {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return "", errors.New("Header, body and signature must all be set")
	}
	return split[2], nil
}

func hashSHA256(in []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(in)
	if err != nil {
		return []byte{}, errorsx.WithStack(err)
	}
	return hash.Sum([]byte{}), nil
}

func decodeToken(token string, verificationKey any) (*jwt.Token, error) {
	keyFunc := func(*jwt.Token) (any, error) { return verificationKey, nil }
	return jwt.ParseWithClaims(token, jwt.MapClaims{}, keyFunc)
}

func validateToken(tokenStr string, verificationKey any) (string, error) {
	_, err := decodeToken(tokenStr, verificationKey)
	if err != nil {
		return "", err
	}
	return getTokenSignature(tokenStr)
}

func generateToken(claims jwt.MapClaims, header jwt.Mapper, signingMethod jose.SignatureAlgorithm, privateKey any) (rawToken string, sig string, err error) {
	if header == nil || claims == nil {
		err = errors.New("Either claims or header is nil.")
		return
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header = assign(token.Header, header.ToMap())

	rawToken, err = token.SignedString(privateKey)
	if err != nil {
		return
	}

	sig, err = getTokenSignature(rawToken)
	return
}

func assign(a, b map[string]interface{}) map[string]interface{} {
	for k, w := range b {
		if _, ok := a[k]; ok {
			continue
		}
		a[k] = w
	}
	return a
}
