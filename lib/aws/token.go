package main

import (
	"container/list"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/bernard-wagner/kms11mod/internal/backend"
)

type AWSKMSToken struct {
	client *kms.KMS
}

func (b *AWSKMSToken) FindObjectsInit() (backend.Iterator, error) {
	prelist := list.New()
	for _, arn := range strings.Split(os.Getenv("AWS_KMS_ARN"), ",") {
		prelist.PushBack(arn)
	}
	return &objectIterator{queue: list.New(), client: b.client, preload: prelist}, nil
}
