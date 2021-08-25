package centrify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/centrify/platform-go-sdk/testutils"
)

type DMCTestSuite struct {
	testutils.CfyTestSuite
	vaultToken string
}

type BackendConfigWithSecretField struct {
	AppID                string `json:"app_id"`
	ClientID             string `json:"client_id"`
	ClientSecret         string `json:"client_secret"`
	RolesAsPolicies      bool   `json:"roles_as_policies"`
	Scope                string `json:"scope"`
	ServiceURL           string `json:"service_url"`
	PolicyPrefix         string `json:"policy_prefix"`
	UseMachineCredential bool   `json:"use_machine_credential"`
}

type loginRequestBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *DMCTestSuite) SetupSuite() {
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

func (s *DMCTestSuite) TestUseMachineCredentialREST() {
	t := s.T()
	s.RequiresActiveTenant()
	s.RequiresVault()

	loginBody, _ := json.Marshal(loginRequestBody{
		Username: s.Config.PASuser.Username,
		Password: s.Config.PASuser.Password,
	})

	// login must succeed
	statusCode, responseBytes := restVault(t, "POST", "/v1/auth/centrify/login", loginBody, "")

	loginResponse := &authVaultLoginResponse{}
	mustUnmarshal(t, responseBytes, loginResponse)

	token := loginResponse.Auth.ClientToken

	s.Assert().Equal(200, statusCode)
	s.Assert().NotNil(loginResponse.Auth.Policies)

	secretName := fmt.Sprintf("%s%d_rest_api", testSecretPrefix, time.Now().Unix())
	secretValue := fmt.Sprintf("test_val_for_%s", secretName)

	restVault(t, "POST", "/v1/centrify/"+secretName, []byte(`{"value": "`+secretValue+`"}`), token)

	// try to login
	statusCode, responseBytes = restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")

	loginResponse = &authVaultLoginResponse{}
	mustUnmarshal(t, responseBytes, loginResponse)

	s.Assert().Equal(200, statusCode)
	s.Assert().NotNil(loginResponse.Auth.Policies)
}

func (s *DMCTestSuite) TestUseMachineCredentialCLI() {
	t := s.T()
	s.RequiresActiveTenant()
	s.RequiresVault()

	token := cliVaultLogin(t, s.vaultToken)

	cliVault(t, token, "write", "auth/centrify/config", "use_machine_credential=true")

	token2 := cliVaultLogin(t, "-format=json", "-method=centrify", "username="+s.Config.PASuser.Username,
		"password="+s.Config.PASuser.Password)

	secretName := fmt.Sprintf("%s%d", testSecretPrefix, time.Now().Unix())
	secretValue := fmt.Sprintf("test_val_for_%s", secretName)

	out := cliVault(t, token2, "write", fmt.Sprintf("centrify/%s", secretName),
		fmt.Sprintf("value=%s", secretValue))

	if !strings.Contains(string(out), `Success! Data written to`) {
		t.Fatal("wrong result for the command 'write'")
	}

	// return configuration back
	cliVault(t,
		token,
		"write",
		"auth/centrify/config",
		"app_id="+s.Config.AppID,
		"client_id="+s.Config.ClientID,
		"client_secret="+s.Config.ClientSecret,
		"scope="+s.Config.AppID,
		"service_url="+s.Config.TenantURL,
		"use_machine_credential=false",
		"policies=all_users",
	)

}

func TestDMCTestSuite(t *testing.T) {
	suite.Run(t, new(DMCTestSuite))
}
