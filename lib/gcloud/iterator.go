package main

import (
	"container/list"
	"context"
	"fmt"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/sirupsen/logrus"
	"github.com/bernard-wagner/kms11mod/internal/backend"
	"google.golang.org/api/iterator"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type objectIterator struct {
	ctx                  context.Context
	preload              *list.List
	queue                *list.List
	client               *kms.KeyManagementClient
	keyRingIterator      *kms.KeyRingIterator
	cryptoKeyIter        *kms.CryptoKeyIterator
	cryptoKeyVersionIter *kms.CryptoKeyVersionIterator
	keyRing              string
	keyName              string
	keyVersion           string
	labels               map[string]string
}

func (i *objectIterator) Next() (backend.Object, error) {
	for {
		if i.queue.Len() > 0 {
			el := i.queue.Front()
			obj := i.queue.Remove(el)
			return obj, nil
		}

		if i.preload.Len() > 0 {
			keyEL := i.preload.Front()
			key := i.preload.Remove(keyEL)

			cryptoKeyVersion, err := i.client.GetCryptoKeyVersion(i.ctx, &kmspb.GetCryptoKeyVersionRequest{Name: key.(string)})
			if err != nil {
				return nil, err
			}

			if cryptoKeyVersion.State == kmspb.CryptoKeyVersion_ENABLED {
				label := i.labels[strings.Split(cryptoKeyVersion.GetName(), "/cryptoKeyVersions")[0]]

				objs, err := cryptoKeyVersionToObjects(i.client, cryptoKeyVersion, label)
				if err != nil {
					return nil, err
				}

				for _, obj := range objs {
					logrus.Trace(obj)
					i.queue.PushBack(obj)
				}
			}
			continue
		}

		if i.cryptoKeyVersionIter != nil {
			cryptoKeyVersion, err := i.cryptoKeyVersionIter.Next()
			if err != nil && err != iterator.Done {
				return nil, err
			}

			if err == iterator.Done {
				if i.cryptoKeyVersionIter.PageInfo().Remaining() > 0 {
					i.cryptoKeyVersionIter = i.client.ListCryptoKeyVersions(i.ctx, &kmspb.ListCryptoKeyVersionsRequest{
						Parent:    strings.Split(cryptoKeyVersion.GetName(), "/cryptoKeyVersions")[0],
						PageToken: i.cryptoKeyVersionIter.PageInfo().Token,
					})
					continue
				}
				i.cryptoKeyVersionIter = nil
				continue
			}

			if cryptoKeyVersion.State == kmspb.CryptoKeyVersion_ENABLED {
				label := i.labels[strings.Split(cryptoKeyVersion.GetName(), "/cryptoKeyVersions")[0]]

				objs, err := cryptoKeyVersionToObjects(i.client, cryptoKeyVersion, label)
				if err != nil {
					return nil, err
				}

				for _, obj := range objs {
					i.queue.PushBack(obj)
				}
			}
			continue
		}

		if i.cryptoKeyIter != nil {
			cryptoKey, err := i.cryptoKeyIter.Next()
			if err != nil && err != iterator.Done {
				return nil, err
			}

			if err == iterator.Done {
				if i.cryptoKeyIter.PageInfo().Remaining() > 0 {
					req := &kmspb.ListCryptoKeysRequest{
						Parent:    strings.Split(cryptoKey.GetName(), "/cryptoKeys")[0],
						PageToken: i.cryptoKeyIter.PageInfo().Token,
					}
					i.cryptoKeyIter = i.client.ListCryptoKeys(i.ctx, req)
					continue
				}
				i.cryptoKeyIter = nil
				continue
			}

			var filter string
			if i.keyVersion != "" {
				filter = fmt.Sprintf("name=%s", fmt.Sprintf("%s/cryptoKeyVersions/%s", cryptoKey.Name, i.keyVersion))
			}

			i.cryptoKeyVersionIter = i.client.ListCryptoKeyVersions(i.ctx, &kmspb.ListCryptoKeyVersionsRequest{
				Parent: cryptoKey.Name,
				Filter: filter,
			})

			continue
		}

		if i.keyRingIterator != nil {
			keyRing, err := i.keyRingIterator.Next()
			if err != nil && err != iterator.Done {
				return nil, err
			}

			if err == iterator.Done {
				if i.keyRingIterator.PageInfo().Remaining() > 0 {
					req := &kmspb.ListKeyRingsRequest{
						Parent:    strings.Split(keyRing.GetName(), "/keyRings")[0],
						PageToken: i.keyRingIterator.PageInfo().Token,
					}
					i.keyRingIterator = i.client.ListKeyRings(i.ctx, req)
					continue
				}
				i.keyRingIterator = nil
				continue
			}

			var filter string
			if i.keyName != "" {
				filter = fmt.Sprintf("name=%s", fmt.Sprintf("%s/cryptoKeys/%s", keyRing.Name, i.keyName))
			}

			i.cryptoKeyIter = i.client.ListCryptoKeys(i.ctx, &kmspb.ListCryptoKeysRequest{
				Parent: keyRing.Name,
				Filter: filter,
			})
			continue
		}
		return nil, nil
	}
}
