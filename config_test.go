package centrify

import (
	"testing"

	"github.com/centrify/platform-go-sdk/testutils"
	"github.com/stretchr/testify/suite"
)

type authVaultLoginResponse struct {
	Auth struct {
		Accessor      string `json:"accessor"`
		ClientToken   string `json:"client_token"`
		EntityID      string `json:"entity_id"`
		LeaseDuration int64  `json:"lease_duration"`
		Metadata      struct {
			Username string `json:"username"`
		} `json:"metadata"`
		Orphan        bool     `json:"orphan"`
		Policies      []string `json:"policies"`
		Renewable     bool     `json:"renewable"`
		TokenPolicies []string `json:"token_policies"`
		TokenType     string   `json:"token_type"`
	} `json:"auth"`
	Data          interface{} `json:"data"`
	LeaseDuration int64       `json:"lease_duration"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	RequestID     string      `json:"request_id"`
	Warnings      interface{} `json:"warnings"`
	WrapInfo      interface{} `json:"wrap_info"`
}

type secretsVaultConfigResponse struct {
	Data struct {
		ProxyMode bool `json:"proxy_mode"`
		HTTPLogs  bool `json:"http_logs"`
	} `json:"data"`
	LeaseDuration int64       `json:"lease_duration"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	RequestID     string      `json:"request_id"`
	Warnings      interface{} `json:"warnings"`
}

type ConfigTestSuite struct {
	testutils.CfyTestSuite
	vaultToken string
}

func (s *ConfigTestSuite) SetupSuite() {
	s.LoadConfig()
	s.vaultToken = *testutils.VaultRootToken
}

func (s *ConfigTestSuite) TestReadWriteConfig() {
	t := s.T()
	s.RequiresVault()

	token := cliVaultLogin(t, "-format=json", "-method=centrify", "username="+s.Config.PASuser.Username,
		"password="+s.Config.PASuser.Password)

	cliVault(t, token, "write", "centrify/config", "proxy_mode=false")

	out := cliVault(t, token, "read", "-format=json", "centrify/config")

	cfg := &secretsVaultConfigResponse{}
	mustUnmarshal(t, out, cfg)
	s.Assert().Equal(false, cfg.Data.ProxyMode)

	cliVault(t, token, "write", "centrify/config", "proxy_mode=true")

	out = cliVault(t, token, "read", "-format=json", "centrify/config")

	cfg = &secretsVaultConfigResponse{}
	mustUnmarshal(t, out, cfg)
	s.Assert().Equal(true, cfg.Data.ProxyMode)

	cliVault(t, token, "write", "centrify/config", "http_logs=true")

	out = cliVault(t, token, "read", "-format=json", "centrify/config")

	cfg = &secretsVaultConfigResponse{}
	mustUnmarshal(t, out, cfg)
	s.Assert().Equal(true, cfg.Data.HTTPLogs)

	cliVault(t, token, "write", "centrify/config", "http_logs=false")

	out = cliVault(t, token, "read", "-format=json", "centrify/config")

	cfg = &secretsVaultConfigResponse{}
	mustUnmarshal(t, out, cfg)
	s.Assert().Equal(false, cfg.Data.HTTPLogs)
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}
