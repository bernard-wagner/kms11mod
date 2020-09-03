package main

import (
	"container/list"
	"context"

	mgmt "github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2018-02-14/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/bernard-wagner/kms11mod/internal/backend"
)

type AzureToken struct {
	client     keyvault.BaseClient
	mgmtClient mgmt.VaultsClient
	settings   auth.EnvironmentSettings
}

func (b *AzureToken) FindObjectsInit() (backend.Iterator, error) {
	rpVaults, err := b.mgmtClient.List(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	return &objectIterator{queue: list.New(), client: b.client, settings: b.settings, mgmtClient: b.mgmtClient, vaultIterator: mgmt.NewResourceListResultIterator(rpVaults)}, nil
}
