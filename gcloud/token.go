package main

import (
	"container/list"
	"context"
	"fmt"
	"os"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/bernard-wagner/kms11mod/kms11"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type GoogleToken struct {
	client     *kms.KeyManagementClient
	location   string
	project    string
	keyRing    string
	keyName    string
	keyVersion string
	preload    []string
}

func (b *GoogleToken) FindObjectsInit() (kms11.Iterator, error) {
	ctx := context.Background()

	preload := list.New()
	for _, key := range strings.Split(os.Getenv("GOOGLE_KEY_ID"), ",") {
		if len(key) > 0 {
			preload.PushBack(key)
		}
	}

	req := &kmspb.ListKeyRingsRequest{
		Parent: parentResourceID(b.project, b.location),
	}

	if b.keyRing != "" {
		req.Filter = fmt.Sprintf("name=%s", fmt.Sprintf("%s/keyRings/%s", parentResourceID(b.project, b.location), b.keyRing))
	}

	return &objectIterator{
		ctx:             context.Background(),
		client:          b.client,
		preload:         preload,
		queue:           list.New(),
		keyRingIterator: b.client.ListKeyRings(ctx, req),
		keyRing:         b.keyRing,
		keyName:         b.keyName,
		keyVersion:      b.keyVersion,
		labels:          make(map[string]string),
	}, nil
}

func parentResourceID(project string, location string) string {
	return fmt.Sprintf("projects/%s/locations/%s", project, location)
}
