package main

import (
	"os"
	"strconv"
	"strings"

	mgmt "github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2018-02-14/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/sirupsen/logrus"
	"github.com/bernard-wagner/kms11mod/kms11"
	"github.com/bernard-wagner/kms11mod/pkcs11mod"
)

// GetAuthorizer creates an Authorizer configured from environment variables in the order:
// 1. Client credentials
// 2. Client certificate
// 3. Username password
// 4. CLI
// 5. MSI
func GetAuthorizerWithResource(settings auth.EnvironmentSettings, resource string) (autorest.Authorizer, error) {
	if strings.HasSuffix(resource, "/") {
		resource = strings.TrimSuffix(resource, "/")
	}

	settings.Values[auth.Resource] = resource

	//1.Client Credentials
	if c, e := settings.GetClientCredentials(); e == nil {
		return c.Authorizer()
	}

	//2. Client Certificate
	if c, e := settings.GetClientCertificate(); e == nil {
		return c.Authorizer()
	}

	//3. Username Password
	if c, e := settings.GetUsernamePassword(); e == nil {
		return c.Authorizer()
	}

	//4. CLI
	if c, e := auth.NewAuthorizerFromCLIWithResource(settings.Values[auth.Resource]); e == nil {
		return c, e
	}

	// 4. MSI
	return settings.GetMSI().Authorizer()
}

func init() {
	if env := os.Getenv("AZURE_VERBOSE_LOGGING"); env != "" {
		if i, err := strconv.Atoi(env); err == nil {
			if i > 0 {
				logrus.SetLevel(logrus.TraceLevel)
				logrus.SetReportCaller(true)
			}
		}
	}

	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		logrus.WithError(err).Trace("failed to get settings from environment")
		return
	}

	mgmtAuthorizer, err := GetAuthorizerWithResource(settings, settings.Environment.ServiceManagementEndpoint)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"ServiceManagementEndpoint": settings.Environment.ServiceManagementEndpoint}).Trace("failed to get config for service management endpoint")
		return
	}

	mgmtClient := mgmt.NewVaultsClient(settings.GetSubscriptionID())
	mgmtClient.Authorizer = mgmtAuthorizer

	vaultAuthorizer, err := GetAuthorizerWithResource(settings, settings.Environment.KeyVaultEndpoint)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"KeyVaultEndpoint": settings.Environment.KeyVaultEndpoint}).Trace("failed to get config for keyvault endpoint")
		return
	}
	client := keyvault.New()
	client.Authorizer = vaultAuthorizer

	pkcs11mod.SetBackend(kms11.NewToken(&AzureToken{
		mgmtClient: mgmtClient,
		client:     client,
		settings:   settings,
	}))
}

func main() {

}
