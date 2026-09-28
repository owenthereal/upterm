package testhelpers

import (
	"context"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/consul/api"
)

const (
	// ConsulHealthCheckTimeout is the timeout for Consul health checks
	ConsulHealthCheckTimeout = 2 * time.Second
)

// IsConsulAvailable checks if Consul is running and accessible with timeout handling
func IsConsulAvailable() bool {
	config := api.DefaultConfig()
	consulURLStr := ConsulURL()
	u, err := url.Parse(consulURLStr)
	if err != nil {
		return false
	}
	config.Address = u.Host

	client, err := api.NewClient(config)
	if err != nil {
		return false
	}

	// Try to get leader with timeout - simple health check
	ctx, cancel := context.WithTimeout(context.Background(), ConsulHealthCheckTimeout)
	defer cancel()

	done := make(chan bool, 1)
	go func() {
		_, err = client.Status().Leader()
		done <- err == nil
	}()

	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		return false
	}
}

// ConsulURL returns the Consul URL from environment or default
func ConsulURL() string {
	addr := os.Getenv("CONSUL_URL")
	if addr == "" {
		addr = "http://localhost:8500"
	}
	return addr
}

// ConsulClient creates a new Consul API client
func ConsulClient() (*api.Client, error) {
	config := api.DefaultConfig()
	consulURL, err := url.Parse(ConsulURL())
	if err != nil {
		return nil, err
	}
	config.Address = consulURL.Host

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}
