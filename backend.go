package centrify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/centrify/cloud-golang-sdk/oauth"
	"github.com/centrify/platform-go-sdk/secret"
)

var errNotCentrifyUser = errors.New("not a Centrify User")

const minTokenSchemaVersion = 1 // required minimum version of token schema

// New returns a new backend as an interface. This func
// is only necessary for builtin backend plugins.
func New() (interface{}, error) {
	return Backend(nil), nil
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	b.Logger().Debug("logical backend instance created")
	return b, nil
}

// FactoryType is a wrapper func that allows the Factory func to specify
// the backend type for the mock backend plugin instance.
func FactoryType(backendType logical.BackendType) func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := Backend(conf)
		b.BackendType = backendType
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// A UserToken is a combo of the User, the actual oauth token response, and the time at which the token is no longer valid
type UserToken struct {
	User      string
	Token     *oauth.TokenResponse
	ExpiresAt time.Time
}

// Backend returns a private embedded struct of framework.Backend.
func Backend(conf *logical.BackendConfig) *backend {
	var b backend
	b.conf = conf
	b.Backend = &framework.Backend{
		Help: "",
		Paths: []*framework.Path{
			pathConfig(&b),
			pathVersion(&b),
			pathCentrify(&b),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	return &b
}

type backend struct {
	*framework.Backend
	conf *logical.BackendConfig
}

func (b *backend) Initialize(ctxt context.Context, req *logical.InitializationRequest) error {
	b.Logger().Info(
		"Centrify Secrets plugin",
		"version", pluginVersion,
		"build", pluginGitCommit,
	)
	return nil
}

func (b *backend) getSecretClient(ctx context.Context, req *logical.Request) (secret.Secret, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	httpClient := b.getHTTPFactory(config)

	tenantURL, _, token, err := b.checkMachCred(httpClient)
	if err != nil {
		b.Logger().Debug("Error in checking machine credential")
		return nil, fmt.Errorf("Error in verifying machine credential for machine: %v", err)
	}

	b.Logger().Debug("centrify", "user", req.DisplayName, "op", req.Operation, "key", req.Path)
	b.Logger().Debug("Requester information", "Entity ID", req.EntityID, "Token accessor", req.ClientTokenAccessor, "Token", req.ClientToken)
	if req.DisplayName == "" {
		b.Logger().Debug("No requester user name information")
		return nil, errors.New("Unknown user")
	}

	var entity *logical.Entity // user entity

	if req.EntityID == "" {
		b.Logger().Debug("No entity ID found", "user", req.DisplayName)
	} else {
		// user that has an entity...check entity ID
		system := b.System()
		entity, err = system.EntityInfo(req.EntityID)
		if err != nil {
			b.Logger().Error("Error in getting entity", "ID", req.EntityID)
		} else {
			b.Logger().Debug("Got Entity object", "ID", entity.ID, "Name", entity.Name, "metadata length", len(entity.Metadata))
			metadata := entity.GetMetadata()
			b.Logger().Debug("metadata", "length", len(metadata))
		}
	}

	if entity != nil {
		val, err := b.getUserTokenFromEntity(entity)
		if err == nil {
			// centrify user
			b.Logger().Debug("centrify: using authenticated user's token to interact with service", "user", req.DisplayName)

			// create a secret client to interaction with backend
			cl, err := secret.NewSecretClient(tenantURL, "pas", val.Token.AccessToken, httpClient)
			if err != nil {
				b.Logger().Error(fmt.Sprintf("Error creating secret client: %+v", err))
				return nil, err
			}
			return cl, nil
		} else if err != errNotCentrifyUser {
			b.Logger().Error("Cannot get user token from entity", "error", err)
			return nil, err
		}
		// not centrify user.. fall through
	}

	// either there is no user entity in the request, or the user is not a Centrify user, check if
	// proxy mode is supported...
	if config.DisableProxyMode {
		b.Logger().Debug("Proxy mode not enabled, no access")
		return nil, errors.New("Non-PAS user is not supported when proxy mode is disabled")
	}

	cl, err := secret.NewSecretClient(tenantURL, "pas", token, httpClient)
	if err != nil {
		return nil, err
	}

	return cl, nil
}

func (b *backend) getUserTokenFromEntity(entity *logical.Entity) (token *UserToken, err error) {
	if entity == nil {
		return nil, errors.New("no entity provided")
	}

	var alias *logical.Alias
	aliases := entity.GetAliases()
	for _, als := range aliases {
		if als.GetMountType() == "centrify" {
			alias = als
			break
		}
	}
	if alias == nil {
		b.Logger().Debug("Not a centrify user")
		return nil, errNotCentrifyUser
	}

	details := alias.GetMetadata()
	result := &UserToken{
		User: alias.GetName(),
	}

	tokenVersion, ok := details["TokenVersion"]
	if !ok {
		return nil, errors.New("Incompatible version of authentication plugin (missing token version). Please upgrade authentication plugin to latest version")
	}

	tv, err := strconv.Atoi(tokenVersion)
	if err != nil {
		return nil, errors.New("Incompatible version of authentication plugin (token version is not integer). Please upgrade authentication plugin to latest version")
	}
	if tv < minTokenSchemaVersion {
		b.Logger().Error("Token schema version: %d, requires at least %d", tv, minTokenSchemaVersion)
		return nil, errors.New("Incompatible version of authentication plugin (token version not supported). Please upgrade authentication plugin to latest version")
	}

	expiresAt, ok := details["ExpiresAt"]
	if !ok {
		return nil, errors.New("No ExpiresAt in saved metadata")
	}
	result.ExpiresAt, err = time.Parse(time.ANSIC, expiresAt)
	if err != nil {
		b.Logger().Error("unexpected format in ExpiresAt", "error", err.Error())
		return nil, errors.New("Unexpected format in ExpiresAt")
	}
	timeNow := time.Now().UTC()
	if timeNow.After(result.ExpiresAt) {
		return nil, errors.New("Token is expired. Please login again.")
	}

	result.Token = &oauth.TokenResponse{}

	result.Token.TokenType, ok = details["TokenType"]
	if !ok {
		return nil, errors.New("No TokenType in saved metadata")
	}

	expiresIn, ok := details["ExpiresIn"]
	if !ok {
		return nil, errors.New("No ExpiresIn in saved metadata")
	}
	result.Token.ExpiresIn, err = strconv.Atoi(expiresIn)
	if err != nil {
		b.Logger().Error("unexpected format in ExpiresIn", "error:", err.Error())
		return nil, errors.New("unexpected format in ExpiresIn")
	}

	result.Token.AccessToken = b.reconstructToken(details, "access_token_")
	result.Token.RefreshToken = b.reconstructToken(details, "refresh_token_")
	return result, nil
}

func (b *backend) reconstructToken(metadata map[string]string, prefix string) string {
	result := ""
	index := 0
	for {
		key := fmt.Sprintf("%s%d", prefix, index)
		tempstr, ok := metadata[key]
		if !ok {
			// key does not exist, return
			return result
		}
		result = result + tempstr
		index++
	}
	return result // should not get here
}

func (b *backend) getHTTPFactory(config *config) func() *http.Client {
	httpClient := cleanhttp.DefaultClient

	if config.HTTPLogs {
		logger := b.Logger().Named("http-log-client")
		httpClient = newLogClient(logger)
	}
	return httpClient
}
