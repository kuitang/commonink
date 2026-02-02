// Package s3client provides a thin S3 client wrapper for object storage operations.
// For production, configure with Tigris endpoint. For tests, use gofakes3.
package s3client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ErrObjectNotFound is returned when a requested object does not exist.
var ErrObjectNotFound = errors.New("s3client: object not found")

// Client wraps an S3 client with bucket and URL configuration.
type Client struct {
	s3Client   *s3.Client
	bucketName string
	publicURL  string // Base URL for public access (e.g., "https://bucket.fly.storage.tigris.dev")
}

// Config holds the configuration for creating an S3 client.
type Config struct {
	// Endpoint is the S3 endpoint URL (e.g., "https://fly.storage.tigris.dev" for Tigris).
	// Leave empty to use default AWS S3.
	Endpoint string
	// Region is the AWS region (e.g., "auto" for Tigris, "us-east-1" for AWS).
	Region string
	// AccessKeyID is the S3 access key.
	AccessKeyID string
	// SecretAccessKey is the S3 secret key.
	SecretAccessKey string
	// BucketName is the bucket to use for storage.
	BucketName string
	// PublicURL is the base URL for publicly accessible objects.
	PublicURL string
	// UsePathStyle enables path-style addressing (required for some S3-compatible services).
	// Set to true for gofakes3, false for Tigris.
	UsePathStyle bool
}

// New creates a new S3 client with the given configuration.
func New(ctx context.Context, cfg Config) (*Client, error) {
	var opts []func(*config.LoadOptions) error

	opts = append(opts, config.WithRegion(cfg.Region))

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	sdkConfig, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(sdkConfig, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
	})

	return &Client{
		s3Client:   s3Client,
		bucketName: cfg.BucketName,
		publicURL:  strings.TrimSuffix(cfg.PublicURL, "/"),
	}, nil
}

// NewFromS3Client creates a Client from an existing S3 client.
// This is useful for testing with gofakes3.
func NewFromS3Client(s3Client *s3.Client, bucketName, publicURL string) *Client {
	return &Client{
		s3Client:   s3Client,
		bucketName: bucketName,
		publicURL:  strings.TrimSuffix(publicURL, "/"),
	}
}

// PutObject stores content under the given key with the specified content type.
// The key should be a unique identifier (e.g., "avatars/user123.png").
func (c *Client) PutObject(ctx context.Context, key string, content []byte, contentType string) error {
	_, err := c.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(c.bucketName),
		Key:         aws.String(key),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(contentType),
		ACL:         types.ObjectCannedACLPublicRead,
	})
	if err != nil {
		return fmt.Errorf("s3client: failed to put object %q: %w", key, err)
	}
	return nil
}

// GetObject retrieves the content stored under the given key.
// Returns ErrObjectNotFound if the key does not exist.
func (c *Client) GetObject(ctx context.Context, key string) ([]byte, error) {
	result, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, ErrObjectNotFound
		}
		// Also check for NotFound error message pattern
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return nil, ErrObjectNotFound
		}
		return nil, fmt.Errorf("s3client: failed to get object %q: %w", key, err)
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("s3client: failed to read object body %q: %w", key, err)
	}
	return data, nil
}

// DeleteObject removes the object at the given key.
// Returns nil if the object was deleted or did not exist.
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	_, err := c.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3client: failed to delete object %q: %w", key, err)
	}
	return nil
}

// GetPublicURL returns the publicly accessible URL for the given key.
func (c *Client) GetPublicURL(key string) string {
	return c.publicURL + "/" + strings.TrimPrefix(key, "/")
}

// BucketName returns the configured bucket name.
func (c *Client) BucketName() string {
	return c.bucketName
}
