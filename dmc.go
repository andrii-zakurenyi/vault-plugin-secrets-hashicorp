package centrify

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/centrify/cloud-golang-sdk/restapi"
	"github.com/centrify/platform-go-sdk/dmc"
	"github.com/centrify/platform-go-sdk/utils"
)

const (
	centrifyVaultScope = "__centrify_vault"

	minCClientVersion = "21.4"

	// sourceHeader defines value of header used in REST API calls.
	sourceHeader = "vault-plugin-secrets-centrify"

	defaultAppID = "vault_io_integration"
	defaultScope = "vault_io_integration"
)

func (b *backend) getCurrentMachineInfo(token, serviceURL string, httpFactory func() *http.Client) (string, error) {
	b.Logger().Debug("getting information about Centrify Client", "serviceURL", serviceURL)

	restClient, err := restapi.GetNewRestClient(serviceURL, httpFactory)
	if err != nil {
		return "", err
	}

	restClient.Headers["Authorization"] = "Bearer " + token
	restClient.SourceHeader = sourceHeader

	b.Logger().Debug("Verify service account of current machine")
	whoami, err := restClient.CallGenericMapAPI("/security/whoami", nil)
	if err != nil {
		return "", err
	}
	name := whoami.Result["User"].(string) //nolint:forcetypeassert
	b.Logger().Debug("Received Client name from PAS", "name", name)
	return name, nil
}

// checkMachCred checks if the plugin can use machine credential
// returns nil/non-nil error on whether the machine credential is obtained
// Other values returned:
//  - serviceURL: service URL
//  - identity:  identity of the machine
//  - token:	 access token
func (b *backend) checkMachCred(httpFactory func() *http.Client) (string, string, string, error) {
	// check if Centrify Client is installed and meets the version requirement
	verOK, err := utils.VerifyCClientVersionReq(minCClientVersion)
	if err != nil {
		b.Logger().Error("Error in checking Centrify Client version", "error", err.Error())
		return "", "", "", err
	}
	if !verOK {
		b.Logger().Error("Centrify Client version requirement not met.", "expects", minCClientVersion)
		return "", "", "", fmt.Errorf("requires Centrify Client version %s or higher", minCClientVersion)
	}

	b.Logger().Debug("Ready to get enrollment information")
	tenantURL, clientID, err := dmc.GetEnrollmentInfo()
	if err != nil {
		b.Logger().Error("Cannot get information about client enrollment", "error", err.Error())
		return "", "", "", err
	}

	tenantURL = "https://" + tenantURL
	b.Logger().Debug("Received information from Centrify Client", "tenantURL", tenantURL, "client ID", clientID)
	token, err := dmc.GetDMCToken(centrifyVaultScope)
	if err != nil {
		b.Logger().Error("GetDMCToken", "Error in getting token", err.Error())
		return "", "", "", err
	}

	b.Logger().Debug("DMC token received")
	// try to get identity from PAS
	nameFromPAS, err := b.getCurrentMachineInfo(token, tenantURL, httpFactory)
	if err != nil {
		b.Logger().Error("GetDMCToken", "Error in getting machine info from PAS", err.Error())
		return "", "", "", err
	}

	// check if name match
	if !strings.EqualFold(nameFromPAS, clientID) {
		b.Logger().Error("GetDMCToken", "name from token", clientID, "name from PAS", nameFromPAS)
		return "", "", "", errors.New("unexpected machine credential token received")
	}

	return tenantURL, clientID, token, nil
}
