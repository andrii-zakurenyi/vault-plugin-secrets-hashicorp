package centrify

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/centrify/platform-go-sdk/secret"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCentrify(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ".*",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCentrifyRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathCentrifyWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCentrifyWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathCentrifyDelete},
			logical.ListOperation:   &framework.PathOperation{Callback: b.pathCentrifyList},
		},
	}
}

func (b *backend) pathCentrifyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("centrify", "op", req.Operation, "path", req.Path)

	secretClient, err := b.getSecretClient(ctx, req)
	if err != nil {
		return nil, err
	}

	if req.Path == "" {
		req.Path = "/" // for top level folder
	}
	secretItems, httpResponse, err := secretClient.List(req.Path)
	if errors.Is(err, secret.ErrFolderNotFound) || errors.Is(err, secret.ErrNotSecretFolder) {
		b.Logger().Debug(err.Error(), "op", req.Operation, "path", req.Path)
		return logical.ErrorResponse(err.Error()), nil
	}
	if err != nil {
		b.logFailedResponse(httpResponse, err)

		return nil, err //nolint:wrapcheck
	}

	vals := []string{}
	for _, secretItem := range secretItems {
		if secretItem.Type == secret.SecretTypeFolder {
			vals = append(vals, secretItem.Name+"/")
		} else {
			vals = append(vals, secretItem.Name)
		}
	}

	return logical.ListResponse(vals), nil
}

func (b *backend) pathCentrifyRead(
	ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("centrify", "op", req.Operation, "path", req.Path, "mount", req.MountPoint)

	secretClient, err := b.getSecretClient(ctx, req)
	if err != nil {
		return nil, err
	}

	secretContent, httpResponse, err := secretClient.Get(req.Path)
	if errors.Is(err, secret.ErrSecretNotFound) {
		b.Logger().Debug(err.Error(), "op", req.Operation, "path", req.Path)
		return logical.ErrorResponse(err.Error()), nil
	}
	if err != nil {
		b.logFailedResponse(httpResponse, err)
		return nil, err //nolint:wrapcheck
	}

	switch secretContentTyped := secretContent.(type) {
	case string:
		return &logical.Response{
			Secret: nil,
			Auth:   nil,
			Data: map[string]interface{}{
				"value": secretContentTyped,
			},
			Redirect: "",
			Warnings: nil,
			WrapInfo: nil,
			Headers:  nil,
		}, nil
	case map[string]string:
		secretKeyPairs := make(map[string]interface{})
		for k, v := range secretContentTyped {
			secretKeyPairs[k] = v
		}

		return &logical.Response{
			Secret:   nil,
			Auth:     nil,
			Data:     secretKeyPairs,
			Redirect: "",
			Warnings: nil,
			WrapInfo: nil,
			Headers:  nil,
		}, nil
	default:
		return nil, secret.ErrSecretTypeNotSupported
	}
}

func (b *backend) pathCentrifyWrite(
	ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("centrify", "op", req.Operation, "path", req.Path)

	// Check that some fields are given
	if len(req.Data) == 0 {
		return logical.ErrorResponse("missing data fields"), nil
	}

	secretClient, err := b.getSecretClient(ctx, req)
	if err != nil {
		return nil, err
	}

	secretName := req.Path
	secretValue := make(map[string]string)
	for k, v := range req.Data {
		if stringValue, ok := v.(string); ok {
			secretValue[k] = stringValue
		}
	}

	// check if secret exists
	_, r, err := secretClient.Get(secretName)

	switch {
	case errors.Is(err, secret.ErrSecretNotFound):
		_, _, r, err = secretClient.Create(secretName, "", secretValue)
		if err != nil {
			b.logFailedResponse(r, err)
			return nil, err //nolint:wrapcheck
		}
	case err != nil:
		b.logFailedResponse(r, err)
		return nil, err //nolint:wrapcheck
	default:
		_, _, r, err = secretClient.Modify(secretName, "", secretValue)
		if err != nil {
			b.logFailedResponse(r, err)
			return nil, err //nolint:wrapcheck
		}
	}

	return nil, nil
}

func (b *backend) pathCentrifyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("centrify", "op", req.Operation, "path", req.Path)

	secretClient, err := b.getSecretClient(ctx, req)
	if err != nil {
		return nil, err
	}

	httpResponse, err := secretClient.Delete(req.Path)
	if errors.Is(err, secret.ErrSecretNotFound) {
		b.Logger().Debug("No secret found to delete", "op", req.Operation, "path", req.Path)
		return nil, nil
	}
	if err != nil {
		b.logFailedResponse(httpResponse, err)
		return nil, err //nolint:wrapcheck
	}
	return nil, nil
}

func (b *backend) logFailedResponse(r *http.Response, err error) {
	body, _ := ioutil.ReadAll(r.Body)
	securedURL := securityCleanURL(r.Request.URL.Path)
	b.Logger().Error(
		"centrify",
		"error", err,
		"status", fmt.Sprintf("%d %s", r.StatusCode, http.StatusText(r.StatusCode)),
		"api", fmt.Sprintf("%s %s", r.Request.Method, securedURL),
	)
	b.Logger().Debug("centrify", "response body", string(body))
}
