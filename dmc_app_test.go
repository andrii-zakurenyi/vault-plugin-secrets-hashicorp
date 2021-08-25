package centrify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/centrify/platform-go-sdk/testutils"
	"github.com/centrify/platform-go-sdk/utils"
	"github.com/centrify/platform-go-sdk/vault"
)

const (
	vaultURL   = "http://localhost:8200"
	testsScope = "testsdk"
)

type authVaultConfigResponse struct {
	Auth          interface{}                  `json:"auth"`
	Data          BackendConfigWithSecretField `json:"data"`
	LeaseDuration int64                        `json:"lease_duration"`
	LeaseID       string                       `json:"lease_id"`
	Renewable     bool                         `json:"renewable"`
	RequestID     string                       `json:"request_id"`
	Warnings      interface{}                  `json:"warnings"`
	WrapInfo      interface{}                  `json:"wrap_info"`
}

type DMCAppTestSuite struct {
	testutils.CfyTestSuite
	vaultToken string
}

func (s *DMCAppTestSuite) SetupSuite() {
	s.LoadConfig()

	// normalize URL
	if !strings.HasPrefix(s.Config.TenantURL, "https://") {
		s.Config.TenantURL = "https://" + s.Config.TenantURL
	}

	u, err := url.Parse(s.Config.TenantURL)
	if err != nil {
		s.T().Skip("Can't parse tenant URL from config")
	}

	s.Config.TenantURL = u.Host
	s.vaultToken = *testutils.VaultRootToken
}

func (s *DMCAppTestSuite) TestDMCAppTokenREST() {
	t := s.T()
	s.RequiresActiveTenant()
	s.RequiresVault()

	ok, err := utils.VerifyCClientVersionReq("21.6")
	s.Require().NoError(err, "Problem with getting cagent version info.")
	if !ok {
		t.Skip("CClient version >= 21.6 is required")
	}

	// write configuration
	respCode, respBody := restVault(
		t, "POST", "/v1/auth/centrify/config",
		[]byte(`{"use_machine_credential": true}`),
		s.vaultToken,
	)
	if respCode != http.StatusNoContent {
		t.Log("response:", string(respBody))
	}
	s.Require().Equal(http.StatusNoContent, respCode)

	token, err := vault.GetHashiVaultToken(testsScope, vaultURL)
	if err != nil {
		t.Error(err)
	}
	s.Require().NotEmpty(token)

	secretName := fmt.Sprintf("%s%d_rest_api", testSecretPrefix, time.Now().Unix())
	secretValue := fmt.Sprintf("test_val_for_%s", secretName)

	respCode, respBody = restVault(t,
		"POST",
		"/v1/centrify/"+secretName,
		[]byte(`{"value": "`+secretValue+`"}`),
		token,
	)
	if respCode != http.StatusNoContent {
		t.Log(string(respBody))
	}
	s.Assert().Equal(http.StatusNoContent, respCode)

	// check config
	_, respBody = restVault(t, "GET", "/v1/auth/centrify/config", nil, s.vaultToken)

	configResponse := &authVaultConfigResponse{}
	err = json.Unmarshal(respBody, configResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().Equal("", configResponse.Data.ClientSecret)
	s.Assert().NotEmpty(configResponse.Data.ClientID)
	s.Assert().Equal(defaultAppID, configResponse.Data.AppID)
	s.Assert().Equal(defaultScope, configResponse.Data.Scope)
	s.Assert().Equal(true, configResponse.Data.UseMachineCredential)
	s.Assert().NotEqual("", configResponse.Data.ServiceURL)

	// write configuration back
	newConfig := BackendConfigWithSecretField{
		AppID:                s.Config.AppID,
		ClientID:             s.Config.ClientID,
		Scope:                s.Config.Scope,
		ClientSecret:         s.Config.ClientSecret,
		ServiceURL:           s.Config.TenantURL,
		UseMachineCredential: false,
	}
	newConfigString, err := json.Marshal(newConfig)
	if err != nil {
		t.Error(err)
	}
	respCode, respBody = restVault(t, "POST", "/v1/auth/centrify/config", newConfigString, s.vaultToken)
	if respCode != http.StatusNoContent {
		t.Log(string(respBody))
	}
	s.Assert().Equal(http.StatusNoContent, respCode)

	// try to login
	loginBody, _ := json.Marshal(loginRequestBody{
		Username: s.Config.PASuser.Username,
		Password: s.Config.PASuser.Password,
	})

	respCode, respBody = restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")
	s.Assert().Equal(http.StatusOK, respCode)

	loginResponse := &authVaultLoginResponse{}
	err = json.Unmarshal(respBody, loginResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotNil(loginResponse.Auth.Policies)
}

func TestDMCAppTestSuite(t *testing.T) {
	suite.Run(t, new(DMCAppTestSuite))
}
