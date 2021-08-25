package centrify

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/centrify/cloud-golang-sdk/oauth"
	"github.com/centrify/platform-go-sdk/secret"
	"github.com/centrify/platform-go-sdk/testutils"
	"github.com/stretchr/testify/suite"
)

const (
	testSecretPrefix = `test_s_`
	mountPoint       = "centrify"
)

type SecretTestSuite struct {
	testutils.CfyTestSuite
	Backend      *backend
	vaultToken   string
	accessToken  string        // access token
	secretClient secret.Secret // interface to secret API
	suffix       string        // random suffix used in this test
	testFolder   string        // path to test folder
	testFolderID string        // test folder ID
}

type readSecretResponse struct {
	RequestID     string            `json:"request_id"`
	LeaseID       string            `json:"lease_id"`
	LeaseDuration int               `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	Data          map[string]string `json:"data"`
	Warnings      interface{}       `json:"warnings"`
}

func (s *SecretTestSuite) SetupSuite() {
	s.LoadConfig()

	s.vaultToken = *testutils.VaultRootToken

	// TODO: handle case of using DMC for testing
	if s.Config.PASuser.Username == "" || s.Config.PASuser.Password == "" {
		s.T().Skip("Must specify username and password for test PAS users")
	}
	if s.Config.AppID == "" {
		s.T().Skip("Must specify an web application for test")
	}

	if s.Config.Scope == "" {
		s.T().Skip("Must specify scope for test")
	}

	var err error

	// get access token for the user
	s.accessToken, err = s.getAccessToken()
	s.Require().NoError(err, "Require Oauth token to continue testing")

	// get secret client for testing
	s.secretClient, err = secret.NewSecretClient(s.Config.TenantURL, secret.ServerPAS, s.accessToken, nil)
	s.Require().NoError(err, "Requires secret client for access to secrets")

	// generate random string as suffix for use in tests
	t := time.Now().UnixNano()
	s.suffix = fmt.Sprintf("-%x", t)
	s.T().Logf("Suffix used in test: [%s]\n", s.suffix)

	folderPath := "Test-folder" + s.suffix
	s.testFolderID = s.createTestFolder(folderPath)
	s.testFolder = folderPath

	s.Config.TenantURL = strings.TrimPrefix(s.Config.TenantURL, "https://")
	s.Config.TenantURL = strings.TrimSuffix(s.Config.TenantURL, "/")
}

func (s *SecretTestSuite) TearDownSuite() {
	t := s.T()
	s.RequiresVault()

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password),
	)

	// get secret list
	stdOut, stdErr, err := cliVaultWithError(t, token, "list", "-format=json", mountPoint+"/"+s.testFolder)
	isNotEmptyList := string(stdOut) != "{}\n"

	if err != nil && isNotEmptyList {
		t.Log("stdout:", string(stdOut))
		t.Log("stderr:", stdErr)
		t.Error("err:", err)
	}

	if len(stdOut) > 0 && isNotEmptyList {
		secrets := []string{}
		mustUnmarshal(t, stdOut, &secrets)

		// delete test secrets
		for _, secretEntity := range secrets {
			if strings.HasPrefix(secretEntity, testSecretPrefix) {
				s.T().Logf("delete test secret: %s", secretEntity)
				cliVault(t, token, "delete", fmt.Sprintf("%s/%s/%s", mountPoint, s.testFolder, secretEntity))
			}
		}
	}

	if s.testFolder != "" {
		if s.secretClient != nil {
			_, err := s.secretClient.Delete(s.testFolder)
			if err != nil {
				s.T().Errorf("Failed to delete test folder: %v", err)
			}
		} else {
			s.T().Error("No secret client to clean up test folder. Logical error in test")
		}
	}
}

func (s *SecretTestSuite) TestRestAPISecretOperations() {
	t := s.T()
	s.RequiresVault()

	loginBody, _ := json.Marshal(loginRequestBody{
		Username: s.Config.PASuser.Username,
		Password: s.Config.PASuser.Password,
	})

	statusCode, responseBytes := restVault(t, "POST", "/v1/auth/centrify/login", loginBody, "")

	s.Assert().Equal(http.StatusOK, statusCode)

	loginResponse := &authVaultLoginResponse{}
	mustUnmarshal(t, responseBytes, loginResponse)
	token := loginResponse.Auth.ClientToken

	secretName := fmt.Sprintf("%s%d_rest_api", testSecretPrefix, time.Now().Unix())
	secretValue := fmt.Sprintf("test_val_for_%s", secretName)

	statusCode, _ = restVault(t, "POST", "/v1/centrify/"+s.testFolder+"/"+secretName,
		[]byte(`{"value": "`+secretValue+`"}`), token)

	s.Assert().Equal(http.StatusNoContent, statusCode)

	// read secret without "secret" substring in the URL
	statusCode, responseBytes = restVault(t, "GET", "/v1/centrify/"+s.testFolder+"/"+secretName, nil, token)

	secretResponse := &readSecretResponse{}

	mustUnmarshal(t, responseBytes, secretResponse)

	sv, ok := secretResponse.Data["value"]
	if !ok {
		t.Fatalf("no value for the secret %s", secretName)
	}
	s.Assert().Equal(secretValue, sv)

	// read secret with "secrets" in the path
	statusCode, responseBytes = restVault(t, "GET", "/v1/centrify/secrets/"+s.testFolder+"/"+secretName, nil, token)
	s.Assert().Equal(http.StatusBadRequest, statusCode)

	// Delete secrets check.
	secretPath := "/v1/centrify/" + s.testFolder + "/" + secretName
	deleteHTTPCall := func() error {
		statusCode, responseBytes = restVault(t, "DELETE", secretPath, nil, token)

		if statusCode != http.StatusNoContent {
			return fmt.Errorf("unexpected response status code: %d %s",
				statusCode, http.StatusText(statusCode))
		}
		return nil
	}
	// Call DELETE twice to test idempotency.
	s.Assert().NoError(deleteHTTPCall(), "Delete secrets should not fail.")
	s.Assert().NoError(deleteHTTPCall(), "Delete non-existing (or already deleted) secrets should not fail")
}

func (s *SecretTestSuite) TestCLISecretOperations() {
	t := s.T()
	s.RequiresVault()

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password))

	secretName := fmt.Sprintf("%s%d", testSecretPrefix, time.Now().Unix())
	secretValue := fmt.Sprintf("test_val_for_%s", secretName)

	out := cliVault(t, token, "write", fmt.Sprintf("%s/%s/%s", mountPoint, s.testFolder, secretName),
		fmt.Sprintf("value=%s", secretValue))

	if !strings.Contains(string(out), `Success! Data written to`) {
		t.Fatal("wrong result for the command 'write'")
	}

	// read secret
	out = cliVault(t, token, "read", "-format=json", fmt.Sprintf("%s/%s/%s", mountPoint,
		s.testFolder, secretName))

	secretResponse := &readSecretResponse{}
	mustUnmarshal(t, out, secretResponse)

	sv, ok := secretResponse.Data["value"]
	if !ok {
		t.Fatalf("no value for the secret %s", secretName)
	}
	s.Assert().Equal(secretValue, sv)

	// list secrets and sure that new secret exists in the list
	out = cliVault(t, token, "list", "-format=json", mountPoint+"/"+s.testFolder)

	secrets := []string{}
	mustUnmarshal(t, out, &secrets)
	t.Logf("secrets: %+v", secrets)
	hasSecret := false
	for _, secretEntity := range secrets {
		if secretEntity == secretName {
			hasSecret = true
			break
		}
	}
	if !hasSecret {
		t.Fatalf("no %s in the list of secrets", secretName)
	}

	// read secret with "secrets" in the path
	_, _, err := cliVaultWithError(t, token, "read", "-format=json",
		fmt.Sprintf("%s/secrets/%s/%s", mountPoint, s.testFolder, secretName))
	s.Assert().NotNil(err)

	// Delete secrets check.
	secretPath := fmt.Sprintf("%s/%s/%s", mountPoint, s.testFolder, secretName)
	cliVault(t, token, "delete", secretPath)

	// Delete non-existing (or already deleted) secrets should not fail
	cliVault(t, token, "delete", secretPath)
}

func (s *SecretTestSuite) TestNonPasUserSecretAccess() {
	t := s.T()
	s.Config.TenantURL = strings.TrimPrefix(s.Config.TenantURL, "https://")
	s.Config.TenantURL = strings.TrimSuffix(s.Config.TenantURL, "/")
	s.RequiresVault()
	s.RequiresCClientRunning()
	s.RequiresActiveTenant()
	s.Config.TenantURL = "https://" + s.Config.TenantURL

	// vault login root
	token := cliVaultLogin(t, s.vaultToken)

	// vault write centrify/config proxy_mode=true
	cliVault(t, token, "write", "centrify/config", "proxy_mode=true")

	// vault auth disable userpass
	cliVault(t, token, "auth", "disable", "userpass")

	// vault auth enable userpass
	cliVault(t, token, "auth", "enable", "userpass")

	userpassUsername := "test-userpass-user" + s.suffix
	// vault write auth/userpass/users/seconduser password=abc policies=all_users
	cliVault(t, token, "write", "auth/userpass/users/"+userpassUsername, "password=abc", "policies=all_users")

	// vault login -method=userpass username=test-userpass-user password=abc
	tokenUserpass := cliVaultLogin(t, "-method=userpass", "username="+userpassUsername, "password=abc")

	secretName := "secret-non-pas-user" + s.suffix
	secretValue := "value-non-pas-user" + s.suffix
	// vault write centrify/secretName value=secretValue
	cliVault(t, tokenUserpass, "write", "centrify/"+secretName, "value="+secretValue)

	// vault read -format=json centrify/secretName
	out := cliVault(t, tokenUserpass, "read", "-format=json", "centrify/"+secretName)
	secretResponse := &readSecretResponse{}

	mustUnmarshal(t, out, secretResponse)

	sv, ok := secretResponse.Data["value"]
	if !ok {
		t.Fatalf("no value for the secret %s", secretName)
	}
	s.Assert().Equal(secretValue, sv)

	// vault write centrify/secretName value=secretValue
	cliVault(t, tokenUserpass, "delete", "centrify/"+secretName)

	token = cliVaultLogin(t, s.vaultToken)

	// vault delete auth/userpass/users/seconduser
	cliVault(t, token, "delete", "auth/userpass/users/"+userpassUsername)
}

func (s *SecretTestSuite) TestCLICreateKVSecret() {
	t := s.T()
	s.RequiresVault()
	s.RequiresCClientRunning()

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password))

	for _, testCase := range s.getTestCaseValuesForTestCLICreateKVSecret() {
		kvPath := fmt.Sprintf("%s/%s", mountPoint, testCase.path)

		// put kv secret
		s.cliPutKVSecret(t, token, kvPath, testCase.content)

		// read
		kvValue := s.cliGetKVSecret(t, token, kvPath)
		s.Assert().Equal(testCase.content, kvValue)

		// delete
		s.cliDeleteKVSecret(t, token, kvPath)
	}
}

func (s *SecretTestSuite) getTestCaseValuesForTestCLICreateKVSecret() []struct {
	path    string
	content map[string]string
} {
	return []struct {
		path    string
		content map[string]string
	}{
		{
			path: "top_folder_kv_secret" + s.suffix,
			content: map[string]string{
				"location": "top level folder",
				"foo":      "bar",
			},
		},
		{
			path: s.testFolder + "/test_kv1" + s.suffix,
			content: map[string]string{
				"foo":   "bar",
				"hello": "world",
			},
		},
		{
			path: s.testFolder + "/empty_key" + s.suffix,
			content: map[string]string{
				"": "no_key",
			},
		},
		{
			path: s.testFolder + "/empty_value" + s.suffix,
			content: map[string]string{
				"foo": "",
			},
		},
	}
}

func (s *SecretTestSuite) TestCLIModifyKVSecret() {
	t := s.T()
	path := s.testFolder + "/modify_kv_test"
	origContent := map[string]string{
		"foo":   "bar",
		"hello": "world",
	}
	newContent := map[string]string{
		"bar":   "foo",
		"world": "hello",
	}

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password))

	kvPath := fmt.Sprintf("%s/%s", mountPoint, path)
	s.cliPutKVSecret(t, token, kvPath, origContent)
	// delete
	defer s.cliDeleteKVSecret(t, token, kvPath)

	kvValue := s.cliGetKVSecret(t, token, kvPath)
	s.Assert().Equal(origContent, kvValue)

	s.cliPutKVSecret(t, token, kvPath, newContent)
	kvValue = s.cliGetKVSecret(t, token, kvPath)
	s.Assert().Equal(newContent, kvValue)
}

func (s *SecretTestSuite) TestCLIListKVSecret() {
	t := s.T()
	secretName := "list_kv_test"
	folderPath := mountPoint + "/" + s.testFolder
	kvPath := folderPath + "/" + secretName
	tempSecretContent := map[string]string{
		"foo":   "bar",
		"hello": "world",
	}

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password))

	s.cliPutKVSecret(t, token, kvPath, tempSecretContent)
	// delete
	defer s.cliDeleteKVSecret(t, token, kvPath)

	secretSlice := s.cliListKVSecret(t, token, folderPath)
	s.Assert().NotEmpty(secretSlice)
	s.Assert().Contains(secretSlice, secretName)
}

func (s *SecretTestSuite) TestCLIListKVSecretTopLevelFolder() {
	t := s.T()
	secretName := "list_kv_test_top_level_folder" + s.suffix
	folderPath := mountPoint
	kvPath := folderPath + "/" + secretName
	tempSecretContent := map[string]string{
		"foo":   "bar",
		"hello": "world",
	}

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password))

	s.cliPutKVSecret(t, token, kvPath, tempSecretContent)
	// delete
	defer s.cliDeleteKVSecret(t, token, kvPath)

	secretSlice := s.cliListKVSecret(t, token, folderPath)
	s.Assert().NotEmpty(secretSlice)
	s.Assert().Contains(secretSlice, secretName)
}

func (s *SecretTestSuite) TestCLIListEmptyFolder() {
	t := s.T()

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password))

	folderPath := "empty_folder" + s.suffix
	s.createTestFolder(folderPath)

	defer s.deleteTestFolder(folderPath)

	secretSlice := s.cliListKVSecret(t, token, mountPoint+"/"+folderPath)
	s.Assert().Empty(secretSlice)
}

func (s *SecretTestSuite) TestCLIDeleteKVSecret() {
	t := s.T()
	path := s.testFolder + "/delete_kv_test"
	tempSecretContent := map[string]string{
		"foo":   "bar",
		"hello": "world",
	}

	token := cliVaultLogin(t, "-method=centrify", fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password))

	kvPath := fmt.Sprintf("%s/%s", mountPoint, path)
	s.cliPutKVSecret(t, token, kvPath, tempSecretContent)

	cliVault(t, token, "kv", "delete", kvPath)
}

func TestSecretTestSuite(t *testing.T) {
	suite.Run(t, new(SecretTestSuite))
}

// cliPutKVSecret creates or updates KV secret
// the caller expects the KV secret is created successfully.
func (s *SecretTestSuite) cliPutKVSecret(t *testing.T, token, kvPath string, values map[string]string) {
	t.Helper()
	args := []string{"kv", "put", kvPath}
	for k, v := range values {
		args = append(args, fmt.Sprintf("%s=%s", k, v))
	}

	out := cliVault(t, token, args...)

	s.Assert().Contains(string(out), `Success! Data written to`, "Must have success execution message")
}

func (s *SecretTestSuite) cliGetKVSecret(t *testing.T, token, kvPath string) map[string]string {
	t.Helper()

	out := cliVault(t, token, "kv", "get", "-format=json", kvPath)

	secretResponse := new(readSecretResponse)
	mustUnmarshal(t, out, secretResponse)

	return secretResponse.Data
}

func (s *SecretTestSuite) cliListKVSecret(t *testing.T, token, kvPath string) []string {
	t.Helper()

	stdOut, stdErr, err := cliVaultWithError(t, token, "kv", "list", "-format=json", kvPath)

	secretListResponse := new([]string)
	// In the case with no kv secrets in the folder, we have "{}\n" as the result and exit status 2
	if string(stdOut) == "{}\n" {
		return *secretListResponse
	}

	s.Assert().NoErrorf(err, "KV secret [%s] listing should return no error", kvPath)
	s.Assert().Empty(stdErr)

	mustUnmarshal(t, stdOut, secretListResponse)

	return *secretListResponse
}

// cliDeleteKVSecret removes the KV secret without test failing (just logs the error).
func (s *SecretTestSuite) cliDeleteKVSecret(t *testing.T, token, kvp string) {
	t.Helper()

	cliVault(t, token, "kv", "delete", kvp)
}

// getAccessToken returns the Oauth access token for the user
func (s *SecretTestSuite) getAccessToken() (string, error) {
	if !strings.HasPrefix(s.Config.TenantURL, "https://") {
		s.Config.TenantURL = "https://" + s.Config.TenantURL
	}
	// get oauth token for user
	oauthClient, err := oauth.GetNewConfidentialClient(
		s.Config.TenantURL,
		s.Config.PASuser.Username,
		s.Config.PASuser.Password,
		nil,
	)
	if err != nil {
		s.T().Logf("Error in getting Oauth client: %v", err)
		return "", err
	}

	oauthToken, oauthError, err := oauthClient.ClientCredentials(s.Config.AppID, s.Config.Scope)
	if err != nil {
		s.T().Logf("Error in sending authentication request to server: %v", err)
		return "", err
	}

	if oauthError != nil {
		s.T().Logf("Authentication error: %v.  Description: %v\n", oauthError.Error, oauthError.Description)
		return "", errors.New(oauthError.Error)
	}
	return oauthToken.AccessToken, nil
}

// createTestFolder creates a test folder
// the caller expects the folder is created successfully
func (s *SecretTestSuite) createTestFolder(path string) string {
	success, id, r, err := s.secretClient.CreateFolder(path, "")
	s.Assert().NoErrorf(err, "CreateFolder [%s] should not result in error", path)
	s.Assert().NotEmptyf(id, "ID of created folder [%s] should be returned", path)
	s.Assert().Truef(success, "CreateFolder [%s] should return true for success", path)
	s.Assert().Equalf(201, r.StatusCode, "CreateFolder [%s] should return 201 status", path)
	return id
}

func (s *SecretTestSuite) deleteTestFolder(path string) {
	resp, err := s.secretClient.Delete(path)
	s.Assert().NoErrorf(err, "Delete [%s] should not result in error", path)
	s.Assert().Equal(http.StatusNoContent, resp.StatusCode)

	resp.Body.Close()
}
