// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	_ "embed"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed service_registry.yaml
var serviceRegistryData []byte

// ServiceDefinition describes a service to be health-checked.
type ServiceDefinition struct {
	Name       string `yaml:"name" json:"name"`
	Hostname   string `yaml:"hostname" json:"hostname"`
	Port       int    `yaml:"port" json:"port"`
	HealthPath string `yaml:"health_path" json:"health_path,omitempty"`
	CheckType  string `yaml:"check_type" json:"check_type"` // "http" or "tcp"
	Category   string `yaml:"category" json:"category"`     // platform, business, infrastructure, frontend, monitoring
}

// ServiceRegistry holds all known service definitions.
type ServiceRegistry struct {
	Services []ServiceDefinition `yaml:"services" json:"services"`
}

var (
	registryOnce     sync.Once
	registryInstance *ServiceRegistry
	errRegistry      error
)

// LoadRegistry parses the embedded YAML (or an override file) and returns
// the service registry. It is safe to call from multiple goroutines.
func LoadRegistry() (*ServiceRegistry, error) {
	registryOnce.Do(func() {
		data := serviceRegistryData

		// Allow environment override for K8s / staging / production
		if overridePath := os.Getenv("SERVICE_REGISTRY_PATH"); overridePath != "" {
			if d, err := os.ReadFile(overridePath); err == nil { //nolint:gosec // path is constructed from validated config
				data = d
			}
		}

		reg := &ServiceRegistry{}
		if err := yaml.Unmarshal(data, reg); err != nil {
			errRegistry = fmt.Errorf("parse service registry: %w", err)
			return
		}
		registryInstance = reg
	})
	return registryInstance, errRegistry
}

// HealthURL returns the URL to health-check a service.
func (d ServiceDefinition) HealthURL() string {
	if d.CheckType == "tcp" {
		return fmt.Sprintf("%s:%d", d.Hostname, d.Port)
	}
	path := d.HealthPath
	if path == "" {
		path = "/health"
	}
	return fmt.Sprintf("http://%s:%d%s", d.Hostname, d.Port, path)
}

// IsTCP returns true if this service needs a TCP (not HTTP) health check.
func (d ServiceDefinition) IsTCP() bool {
	return d.CheckType == "tcp"
}

// ByCategory returns services filtered by category.
func (r *ServiceRegistry) ByCategory(cat string) []ServiceDefinition {
	var out []ServiceDefinition
	for _, s := range r.Services {
		if s.Category == cat {
			out = append(out, s)
		}
	}
	return out
}
