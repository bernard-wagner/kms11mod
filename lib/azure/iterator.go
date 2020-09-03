package main

import (
	"container/list"
	"context"
	"fmt"

	mgmt "github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2018-02-14/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/bernard-wagner/kms11mod/internal/backend"
)

type objectIterator struct {
	queue               *list.List
	client              keyvault.BaseClient
	mgmtClient          mgmt.VaultsClient
	settings            auth.EnvironmentSettings
	vaultIterator       mgmt.ResourceListResultIterator
	keyIterator         keyvault.KeyListResultIterator
	versionIterator     keyvault.KeyListResultIterator
	certIterator        keyvault.CertificateListResultIterator
	certVersionIterator keyvault.CertificateListResultIterator
}

func (i *objectIterator) NotDone() bool {
	return i.queue.Len() > 0 || i.vaultIterator.NotDone() || i.certIterator.NotDone() || i.certVersionIterator.NotDone() || i.keyIterator.NotDone() || i.versionIterator.NotDone() || i.vaultIterator.NotDone()
}

func (i *objectIterator) Next() (backend.Object, error) {

	ctx := context.Background()

	for i.NotDone() {
		// First try to return from queue
		if i.queue.Len() > 0 {
			el := i.queue.Front()
			obj := i.queue.Remove(el)
			return obj, nil
		}

		// Iterate over key versions
		if i.versionIterator.NotDone() {

			version := i.versionIterator.Value()
			baseURI, keyName, keyVersion := parseID(*version.Kid)

			resp, err := i.client.GetKey(ctx, baseURI, keyName, keyVersion)
			if err != nil {
				return nil, err
			}

			objs, err := convertJSONWebKeyToObject(i.client, *resp.Key, true)
			if err != nil {
				return nil, err
			}

			for _, obj := range objs {
				i.queue.PushBack(obj)
			}

			if err := i.versionIterator.Next(); err != nil {
				return nil, err
			}

			continue
		}

		// Iterate over keys
		if i.keyIterator.NotDone() {

			key := i.keyIterator.Value()
			baseURI, keyName, _ := parseID(*key.Kid)

			iter, err := i.client.GetKeyVersions(ctx, baseURI, keyName, nil)
			if err != nil {
				return nil, err
			}

			i.versionIterator = keyvault.NewKeyListResultIterator(iter)

			if err := i.keyIterator.Next(); err != nil {
				return nil, err
			}
			continue
		}

		// Iterate over certificate versions
		if i.certVersionIterator.NotDone() {
			version := i.certVersionIterator.Value()

			baseURI, certificateName, certificateVersion := parseID(*version.ID)

			bundle, err := i.client.GetCertificate(ctx, baseURI, certificateName, certificateVersion)
			if err != nil {
				return nil, err
			}

			baseURI, keyName, keyVersion := parseID(*bundle.Kid)

			key, err := i.client.GetKey(ctx, baseURI, keyName, keyVersion)
			if err != nil {
				return nil, err
			}

			objs, err := convertCertificateBundleToObject(i.client, bundle, *key.Key)
			if err != nil {
				return nil, err
			}

			for _, obj := range objs {
				i.queue.PushBack(obj)
			}

			if err := i.certVersionIterator.Next(); err != nil {
				return nil, err
			}
			continue
		}

		// Iterate over certificates
		if i.certIterator.NotDone() {
			cert := i.certIterator.Value()

			baseURI, certificateName, _ := parseID(*cert.ID)

			page, err := i.client.GetCertificateVersions(ctx, baseURI, certificateName, nil)
			if err != nil {
				return nil, err
			}

			i.certVersionIterator = keyvault.NewCertificateListResultIterator(page)
			if err := i.certIterator.Next(); err != nil {
				return nil, err
			}

			continue
		}

		// Iterate over key vaults
		if i.vaultIterator.NotDone() {
			vault := i.vaultIterator.Value()

			baseURI := fmt.Sprintf("https://%s.%s", *vault.Name, i.settings.Environment.KeyVaultDNSSuffix)

			page, err := i.client.GetKeys(ctx, baseURI, nil)
			if err != nil {
				return nil, err
			}

			i.keyIterator = keyvault.NewKeyListResultIterator(page)

			certPage, err := i.client.GetCertificates(ctx, baseURI, nil, nil)
			if err != nil {
				return nil, err
			}

			i.certIterator = keyvault.NewCertificateListResultIterator(certPage)
			if err := i.vaultIterator.Next(); err != nil {
				return nil, err
			}

			continue
		}
	}

	return nil, nil
}
