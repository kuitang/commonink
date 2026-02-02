// Package s3client provides a thin S3 client wrapper for object storage operations.
package s3client

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

// TestClient creates an S3 client backed by gofakes3 for testing.
// The returned client uses an in-memory S3 backend and a test HTTP server.
// The test server is automatically cleaned up when the test completes.
func TestClient(t testing.TB, bucketName string) *Client {
	t.Helper()

	// Create in-memory S3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)

	// Create test HTTP server
	ts := httptest.NewServer(faker.Server())
	t.Cleanup(func() {
		ts.Close()
	})

	// Create S3 client configured for the test server
	ctx := context.Background()
	sdkConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""),
		),
	)
	if err != nil {
		t.Fatalf("failed to load AWS config: %v", err)
	}

	s3Client := s3.NewFromConfig(sdkConfig, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ts.URL)
		o.UsePathStyle = true // Required for gofakes3
	})

	// Create the bucket
	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("failed to create test bucket: %v", err)
	}

	return NewFromS3Client(s3Client, bucketName, ts.URL)
}
