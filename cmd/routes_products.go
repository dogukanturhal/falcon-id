// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/gin-gonic/gin"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

const (
	permPlatformApplicationsRead  = "platform:applications:read"
	permPlatformApplicationsWrite = "platform:applications:write"
)

// registerProductRoutes registers product, license, and app registration routes.
func registerProductRoutes(router *gin.Engine, h *Handlers, authMiddleware *middleware.AuthMiddleware, authRateLimiter *middleware.AuthRateLimiter) {
	// ========== Platform Admin: Product Management ==========
	// Requires platform admin permissions
	platformProducts := router.Group("/api/v1/platform/products")
	platformProducts.Use(authMiddleware.RequireAuth())
	platformProducts.Use(authMiddleware.RequirePermission("platform:products:read"))
	{
		platformProducts.GET("", h.Product.List)
		platformProducts.GET("/:id", h.Product.Get)
		platformProducts.GET("/:id/versions", h.Product.ListVersions)

		write := platformProducts.Group("")
		write.Use(authMiddleware.RequirePermission("platform:products:write"))
		{
			write.POST("", h.Product.Create)
			write.PUT("/:id", h.Product.Update)
			write.DELETE("/:id", h.Product.Delete)
			write.POST("/:id/versions", h.Product.CreateVersion)
		}
	}

	// ========== Platform Admin: License Management ==========
	platformLicenses := router.Group("/api/v1/platform/licenses")
	platformLicenses.Use(authMiddleware.RequireAuth())
	platformLicenses.Use(authMiddleware.RequirePermission("platform:licenses:read"))
	{
		platformLicenses.GET("", h.License.List)
		platformLicenses.GET("/:id", h.License.Get)
		platformLicenses.GET("/:id/activations", h.License.ListActivations)

		write := platformLicenses.Group("")
		write.Use(authMiddleware.RequirePermission("platform:licenses:write"))
		{
			write.POST("", h.License.Create)
			write.PUT("/:id", h.License.Update)
			write.POST("/:id/suspend", h.License.Suspend)
			write.POST("/:id/revoke", h.License.Revoke)
			write.DELETE("/activations/:id", h.License.Deactivate)
		}
	}

	// ========== Platform Admin: App Registrations ==========
	platformAppRegs := router.Group("/api/v1/platform/app-registrations")
	platformAppRegs.Use(authMiddleware.RequireAuth())
	platformAppRegs.Use(authMiddleware.RequirePermission("platform:app-registrations:read"))
	{
		platformAppRegs.GET("", h.AppRegistration.List)
		platformAppRegs.GET("/:id", h.AppRegistration.Get)

		write := platformAppRegs.Group("")
		write.Use(authMiddleware.RequirePermission("platform:app-registrations:write"))
		{
			write.POST("", h.AppRegistration.Create)
			write.PUT("/:id", h.AppRegistration.Update)
			write.POST("/:id/rotate-secret", h.AppRegistration.RotateSecret)
			write.POST("/:id/suspend", h.AppRegistration.Suspend)
			write.POST("/:id/revoke", h.AppRegistration.Revoke)
			write.DELETE("/:id", h.AppRegistration.Delete)
		}
	}

	// ========== Public: License Validation & Activation ==========
	// These endpoints are used by licensed products to phone home.
	// No auth required - authentication is via license key.
	// SECURITY: Rate limited to prevent brute-force license key enumeration.
	licenseRL := authRateLimiter.Middleware()
	publicLicenses := router.Group("/api/v1/licenses")
	{
		publicLicenses.POST("/validate", licenseRL, h.License.Validate)
		publicLicenses.POST("/activate", licenseRL, h.License.Activate)
	}

	// NOTE: Product Instances and Product Database Groups routes have been moved
	// to the db-provisioner service as part of Phase 1c decomposition.

	// ========== Platform Admin: Application Objects (Entra ID-inspired) ==========
	platformApps := router.Group("/api/v1/platform/applications")
	platformApps.Use(authMiddleware.RequireAuth())
	platformApps.Use(authMiddleware.RequirePermission(permPlatformApplicationsRead))
	{
		platformApps.GET("", h.Application.List)
		platformApps.GET("/deleted", h.Application.ListDeleted)
		platformApps.GET("/stale", h.Application.DetectStaleApps)
		platformApps.GET("/:id", h.Application.Get)
		platformApps.GET("/:id/service-principals", h.Application.ListServicePrincipals)
		platformApps.GET("/:id/service-principals/:sp_id", h.Application.GetServicePrincipal)
		platformApps.GET("/:id/consents", h.Application.ListConsents)
		platformApps.GET("/:id/owners", h.Application.ListOwners)
		platformApps.GET("/:id/identity-providers", h.Application.ListAppIdentityProviders)
		platformApps.GET("/:id/sign-in-activity", h.Application.ListAppSignIns)
		platformApps.GET("/:id/service-principals/:sp_id/credentials", h.Application.ListSPCredentials)
		platformApps.GET("/:id/service-principals/:sp_id/sign-in-activity", h.Application.ListSPSignIns)
		platformApps.GET("/:id/roles/assignments", h.AppRole.ListAssignments)

		write := platformApps.Group("")
		write.Use(authMiddleware.RequirePermission(permPlatformApplicationsWrite))
		{
			write.POST("", h.Application.Create)
			write.PUT("/:id", h.Application.Update)
			write.DELETE("/:id", h.Application.Delete)
			write.POST("/:id/restore", h.Application.RestoreApplication)
			write.POST("/:id/service-principals", h.Application.ProvisionServicePrincipal)
			write.POST("/:id/service-principals/bulk", h.Application.BulkProvisionServicePrincipals)
			write.POST("/:id/service-principals/:sp_id/enable", h.Application.EnableServicePrincipal)
			write.POST("/:id/service-principals/:sp_id/disable", h.Application.DisableServicePrincipal)
			write.POST("/:id/service-principals/:sp_id/rotate-credentials", h.Application.RotateServicePrincipalCredentials)
			write.DELETE("/:id/service-principals/:sp_id", h.Application.DeleteServicePrincipal)
			write.POST("/:id/service-principals/:sp_id/credentials", h.Application.AddSPCredential)
			write.DELETE("/:id/service-principals/:sp_id/credentials/:cred_id", h.Application.RevokeSPCredential)
			write.POST("/:id/owners", h.Application.AddOwner)
			write.DELETE("/:id/owners/:owner_id", h.Application.RemoveOwner)
			write.POST("/:id/identity-providers", h.Application.EnableAppIdentityProvider)
			write.DELETE("/:id/identity-providers/:idp_id", h.Application.DisableAppIdentityProvider)
			write.POST("/:id/consent", h.Application.GrantConsent)
			write.DELETE("/:id/consent", h.Application.RevokeConsent)
			write.POST("/:id/verify-publisher", h.Application.VerifyPublisher)
			write.DELETE("/:id/verify-publisher", h.Application.RevokePublisherVerification)
			write.POST("/:id/roles/assignments", h.AppRole.AssignRole)
			write.DELETE("/:id/roles/assignments/:assignment_id", h.AppRole.UnassignRole)
		}
	}

	// ========== Platform Admin: Service Principals by Tenant ==========
	platformSPs := router.Group("/api/v1/platform/service-principals")
	platformSPs.Use(authMiddleware.RequireAuth())
	platformSPs.Use(authMiddleware.RequirePermission(permPlatformApplicationsRead))
	{
		platformSPs.GET("", h.Application.ListServicePrincipalsByTenant)
	}

	// ========== Platform Admin: Credential Lifetime Policies ==========
	credPolicies := router.Group("/api/v1/platform/credential-policies")
	credPolicies.Use(authMiddleware.RequireAuth())
	credPolicies.Use(authMiddleware.RequirePermission(permPlatformApplicationsRead))
	{
		credPolicies.GET("", h.CredentialPolicy.List)
		credPolicies.GET("/platform", h.CredentialPolicy.GetPlatformPolicy)
		credPolicies.GET("/effective", h.CredentialPolicy.GetEffectivePolicy)

		credWrite := credPolicies.Group("")
		credWrite.Use(authMiddleware.RequirePermission(permPlatformApplicationsWrite))
		{
			credWrite.POST("", h.CredentialPolicy.Upsert)
			credWrite.DELETE("/:id", h.CredentialPolicy.Delete)
		}
	}

	// ========== Platform Admin: Credential Usage Analysis ==========
	credAnalysis := router.Group("/api/v1/platform/credential-analysis")
	credAnalysis.Use(authMiddleware.RequireAuth())
	credAnalysis.Use(authMiddleware.RequirePermission(permPlatformApplicationsRead))
	{
		credAnalysis.GET("/usage", h.CredentialAnalysis.AnalyzeUsage)
		credAnalysis.GET("/unused", h.CredentialAnalysis.ListUnused)
	}

	// ========== Platform Admin: Admin Consent Workflow ==========
	consentRequests := router.Group("/api/v1/platform/consent-requests")
	consentRequests.Use(authMiddleware.RequireAuth())
	consentRequests.Use(authMiddleware.RequirePermission(permPlatformApplicationsRead))
	{
		consentRequests.GET("", h.ConsentRequest.List)
		consentRequests.GET("/pending", h.ConsentRequest.ListPending)

		crWrite := consentRequests.Group("")
		crWrite.Use(authMiddleware.RequirePermission(permPlatformApplicationsWrite))
		{
			crWrite.POST("", h.ConsentRequest.Create)
			crWrite.POST("/:id/approve", h.ConsentRequest.Approve)
			crWrite.POST("/:id/deny", h.ConsentRequest.Deny)
		}
	}

	// ========== Platform Admin: Registration Policies ==========
	// Controls how OAuth/OIDC client applications may be registered within the platform.
	regPolicies := router.Group("/api/v1/platform/registration-policies")
	regPolicies.Use(authMiddleware.RequireAuth())
	regPolicies.Use(authMiddleware.RequirePermission(permPlatformApplicationsRead))
	{
		regPolicies.GET("", h.RegistrationPolicy.List)
		regPolicies.GET("/default", h.RegistrationPolicy.GetDefault)
		regPolicies.GET("/:id", h.RegistrationPolicy.Get)

		write := regPolicies.Group("")
		write.Use(authMiddleware.RequirePermission(permPlatformApplicationsWrite))
		{
			write.POST("", h.RegistrationPolicy.Create)
			write.PUT("/:id", h.RegistrationPolicy.Update)
			write.DELETE("/:id", h.RegistrationPolicy.Delete)
		}
	}

	// ========== Admin: Temporary Access Pass Management ==========
	// Allows administrators to issue and revoke short-lived authentication codes
	// for users who are locked out or setting up a new device.
	// SECURITY: Requires authentication and the users:write permission to prevent
	// privilege escalation via TAP issuance.
	adminTAP := router.Group("/api/v1/admin/temp-access-passes")
	adminTAP.Use(authMiddleware.RequireAuth())
	adminTAP.Use(authMiddleware.RequirePermission("users:write"))
	{
		adminTAP.POST("", h.TempAccessPass.Create)
		adminTAP.GET("", h.TempAccessPass.List)
		adminTAP.DELETE("/:id", h.TempAccessPass.Revoke)
	}
}
