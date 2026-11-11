// SPDX-License-Identifier: MIT
// Copyright 2024-2026 CloudSlash Contributors

// Package gcp reads Google Cloud resource metadata with a service account.
// It is provider-specific by design; the core never imports this package.
package gcp

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

// Client is a read-only GCP client bound to one project and service account.
type Client struct {
	Project string
	Compute *compute.Service
	Storage *storage.Service
}

// New builds read-only clients from the plugin-owned connection config.
func New(ctx context.Context, config map[string]string) (*Client, error) {
	project := strings.TrimSpace(config["project_id"])
	credentials := strings.TrimSpace(config["service_account_json"])
	if project == "" {
		return nil, fmt.Errorf("project_id is required")
	}
	if credentials == "" {
		return nil, fmt.Errorf("service_account_json is required")
	}
	options := []option.ClientOption{
		option.WithCredentialsJSON([]byte(credentials)),
		option.WithScopes(compute.CloudPlatformScope, storage.CloudPlatformScope),
	}
	computeService, err := compute.NewService(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("create GCP compute client: %w", err)
	}
	storageService, err := storage.NewService(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("create GCP storage client: %w", err)
	}
	return &Client{Project: project, Compute: computeService, Storage: storageService}, nil
}

// Verify proves the service account can read the project.
func (c *Client) Verify(ctx context.Context) (string, error) {
	if _, err := c.Compute.Projects.Get(c.Project).Do(); err != nil {
		return "", fmt.Errorf("cannot read GCP project %s: %w", c.Project, err)
	}
	return c.Project, nil
}
