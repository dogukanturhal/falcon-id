// SPDX-License-Identifier: AGPL-3.0-or-later

// Package docs holds the Swagger/OpenAPI specification for Falcon ID.
//
// This file is a minimal placeholder that registers an empty spec so the
// service compiles and the /swagger/index.html route is reachable without
// running the swag code generator first.
//
// To generate the full spec from inline annotations, run:
//
//	swag init -g cmd/main.go -o docs/
//
// The generated output will replace this file with a complete OpenAPI 2.0
// document embedded into the binary. Install the CLI once per workstation:
//
//	go install github.com/swaggo/swag/cmd/swag@latest
package docs

import "github.com/swaggo/swag"

// SwaggerInfo holds the exported Swagger specification fields.
// These values are set by the swag code generator; the placeholder values
// below allow the service to boot without running swag init first.
var SwaggerInfo = &swag.Spec{
	Version:          "1.0.0",
	Host:             "",
	BasePath:         "/api/v1",
	Schemes:          []string{},
	Title:            "Falcon ID API",
	Description:      "Falcon ID — Identity & Access Management for Hexxlock Technologies.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}

// docTemplate is a minimal OpenAPI 2.0 document that satisfies the Swagger UI
// renderer. Run `swag init` to replace this with the full generated spec.
const docTemplate = `{
  "swagger": "2.0",
  "info": {
    "description": "{{escape .Description}}",
    "title": "{{.Title}}",
    "contact": {
      "name": "Hexxlock API Support",
      "email": "api-support@hexxlock.com"
    },
    "version": "{{.Version}}"
  },
  "host": "{{.Host}}",
  "basePath": "{{.BasePath}}",
  "paths": {}
}`
