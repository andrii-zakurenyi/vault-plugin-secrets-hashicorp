package centrify

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// configuration parameters
const (
	cfgProxyMode = "proxy_mode"
	cfgHTTPLogs  = "http_logs"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			// Note that this is stored as "disable_proxy_mode" which has the default of false (opposite to this setting)
			cfgProxyMode: {
				Type:        framework.TypeBool,
				Description: "Provides proxy services for non-PAS users to access information stored in Centrify PAS",
				Default:     true,
			},
			cfgHTTPLogs: {
				Type:        framework.TypeBool,
				Description: "Enables logging of HTTP requests. It can be useful for troubleshooting and support",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigCreateOrUpdate},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigCreateOrUpdate},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
		},
	}
}

func (b *backend) pathConfigCreateOrUpdate(
	ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	b.Logger().Debug("pathConfigCreateOrUpdate", "operation", req.Operation)

	var curConfig *config
	var err error

	if req.Operation == logical.CreateOperation {
		curConfig = &config{}
	} else {
		curConfig, err = b.Config(ctx, req.Storage)
		if err != nil {
			b.Logger().Warn("Cannot get existing configuration in update operation. Create new one")
			curConfig = &config{}
		}
	}

	val, ok := data.GetOk(cfgProxyMode)
	if ok {
		curConfig.DisableProxyMode = !val.(bool)
	} else if req.Operation == logical.CreateOperation {
		curConfig.DisableProxyMode = !data.Get(cfgProxyMode).(bool)
	}

	val, ok = data.GetOk(cfgHTTPLogs)
	if ok {
		if v, ok := val.(bool); ok {
			curConfig.HTTPLogs = v
		}
	} else if req.Operation == logical.CreateOperation {
		if v, ok := data.Get(cfgHTTPLogs).(bool); ok {
			curConfig.HTTPLogs = v
		}
	}

	entry, err := logical.StorageEntryJSON("config", curConfig)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("configuration object not found")
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			cfgProxyMode: !config.DisableProxyMode,
			cfgHTTPLogs:  config.HTTPLogs,
		},
	}
	return resp, nil
}

// Config returns the configuration for this backend.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	var result config
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
	}

	return &result, nil
}

type config struct {
	DisableProxyMode bool `json:"disable_proxy_mode" structs:"disable_proxy_mode" mapstructure:"disable_proxy_mode"`
	HTTPLogs         bool `json:"http_logs" structs:"http_logs" mapstructure:"http_logs"`
}
