package main

import (
	"container/list"
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/bernard-wagner/kms11mod/internal/backend"
)

type objectIterator struct {
	queue         *list.List
	client        *kms.KMS
	nextKeyMarker *string
	done          bool
	preload       *list.List
}

func (i *objectIterator) Next() (backend.Object, error) {

	for {
		// First try and read from queue
		if i.queue.Len() > 0 {
			el := i.queue.Front()
			obj := i.queue.Remove(el)
			return obj, nil
		}

		if i.done {
			break
		}

		listKeysReq := &kms.ListKeysInput{Marker: i.nextKeyMarker}

		resp, err := i.client.ListKeysWithContext(context.Background(), listKeysReq)
		if err != nil {
			return nil, err
		}

		keyList := resp.Keys

		for i.preload.Len() > 0 {
			arnEl := i.preload.Front()
			i.preload.Remove(arnEl)
			keyList = append(keyList, &kms.KeyListEntry{
				KeyArn: aws.String(arnEl.Value.(string)),
			})
		}

		for _, keyResult := range keyList {
			key, err := i.client.DescribeKeyWithContext(context.Background(), &kms.DescribeKeyInput{
				KeyId: keyResult.KeyArn,
			})
			if err != nil {
				// If the Key is marked for deletion or disabled, suppress error
				// and don't add to results
				if awsErr, ok := err.(awserr.Error); ok &&
					(awsErr.Code() == kms.ErrCodeInvalidStateException ||
						awsErr.Code() == kms.ErrCodeDisabledException) {
					continue
				}
				return nil, err
			}

			// Symmetric keys are not supported for now
			if *key.KeyMetadata.CustomerMasterKeySpec == kms.CustomerMasterKeySpecSymmetricDefault {
				continue
			}

			pub, err := i.client.GetPublicKeyWithContext(context.Background(), &kms.GetPublicKeyInput{
				KeyId: keyResult.KeyArn,
			})
			if err != nil {
				// If the Key is marked for deletion or disabled, suppress error
				// and don't add to results
				if awsErr, ok := err.(awserr.Error); ok &&
					(awsErr.Code() == kms.ErrCodeInvalidStateException ||
						awsErr.Code() == kms.ErrCodeDisabledException) {
					continue
				}
				return nil, err
			}

			objs, err := convertKeyToObjects(i.client, pub)
			if err != nil {
				return nil, err
			}
			for _, obj := range objs {
				i.queue.PushBack(obj)
			}
		}

		i.nextKeyMarker = resp.NextMarker
		i.done = !*resp.Truncated
	}

	return nil, nil
}
