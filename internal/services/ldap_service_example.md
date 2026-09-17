# LDAP Service Usage Guide

## Overview

The LDAP Service provides direct LDAP/Active Directory integration for the HexxLock IAM service. It supports:

- LDAP/LDAPS connections with TLS/StartTLS
- User authentication against Active Directory
- Automatic user provisioning and synchronization
- Group-to-role mapping
- Configurable attribute mapping

## Setup

### 1. Create an Identity Provider

First, create an identity provider configuration in the database:

```go
provider := &models.IdentityProvider{
    TenantID:    tenantID,
    Type:        "ldap",
    Name:        "corporate-ad",
    DisplayName: "Corporate Active Directory",
    IsActive:    true,
    IsDefault:   true,
    Priority:    100,
    Config: map[string]interface{}{
        // Connection Settings
        "host":            "10.0.20.10",
        "port":            389,
        "use_tls":         false,
        "use_start_tls":   true,
        "skip_tls_verify": false,
        "server_name":     "ad.example.com",
        "bind_dn":         "CN=Service Account,OU=Service Accounts,DC=example,DC=com",
        "bind_password":   "service_account_password",

        // Search Configuration
        "base_dn":          "DC=example,DC=com",
        "user_filter":      "(&(objectClass=user)(sAMAccountName=%s))",
        "user_search_base": "OU=Users,DC=example,DC=com",
        "group_filter":     "(&(objectClass=group)(member=%s))",
        "group_search_base": "OU=Groups,DC=example,DC=com",

        // Attribute Mapping
        "username_attr":     "sAMAccountName",
        "email_attr":        "mail",
        "first_name_attr":   "givenName",
        "last_name_attr":    "sn",
        "display_name_attr": "displayName",
        "phone_attr":        "telephoneNumber",
        "group_attr":        "memberOf",

        // Sync Settings
        "sync_enabled":       true,
        "sync_interval":      60, // minutes
        "sync_groups":        true,
        "create_users":       true,
        "update_users":       true,
        "disable_local_auth": false,

        // Group Mappings (AD Group -> Role Name)
        "group_mappings": map[string]string{
            "Domain Admins":     "admin",
            "IT Managers":       "manager",
            "Developers":        "developer",
            "Support Team":      "support",
            "All Employees":     "user",
        },
    },
}

err := idpRepo.Create(ctx, provider)
```

### 2. Initialize the LDAP Service

```go
ldapService := services.NewLDAPService(
    config,
    idpRepo,
    userRepo,
    roleRepo,
)
```

## Usage Examples

### Authenticate a User

```go
user, err := ldapService.Authenticate(
    ctx,
    tenantID,
    providerID,
    "john.doe",    // username
    "password123", // password
)

if err != nil {
    // Authentication failed
    log.Error("LDAP authentication failed", zap.Error(err))
    return err
}

// User authenticated successfully
log.Info("User authenticated", zap.String("username", user.Username))
```

### Test LDAP Connection

```go
ldapConfig := &models.LDAPConfig{
    Host:            "10.0.20.10",
    Port:            389,
    UseStartTLS:     true,
    BindDN:          "CN=Service Account,OU=Service Accounts,DC=example,DC=com",
    BindPassword:    "password",
    BaseDN:          "DC=example,DC=com",
}

err := ldapService.TestConnection(ctx, ldapConfig)
if err != nil {
    log.Error("LDAP connection test failed", zap.Error(err))
} else {
    log.Info("LDAP connection test successful")
}
```

### Synchronize Users from LDAP

```go
// Full sync
result, err := ldapService.SyncUsers(ctx, providerID, true)
if err != nil {
    log.Error("LDAP sync failed", zap.Error(err))
    return err
}

log.Info("LDAP sync completed",
    zap.Int("users_found", result.UsersFound),
    zap.Int("users_created", result.UsersCreated),
    zap.Int("users_updated", result.UsersUpdated),
    zap.String("duration", result.Duration),
)

if len(result.Errors) > 0 {
    log.Warn("Sync completed with errors", zap.Strings("errors", result.Errors))
}
```

### Search for a User

```go
conn, err := ldapService.Connect(ldapConfig)
if err != nil {
    return err
}
defer conn.Close()

entry, err := ldapService.SearchUser(conn, ldapConfig, "john.doe")
if err != nil {
    log.Error("User search failed", zap.Error(err))
    return err
}

if entry != nil {
    log.Info("User found",
        zap.String("dn", entry.DN),
        zap.String("email", entry.GetAttributeValue("mail")),
    )
}
```

### Get User Groups

```go
conn, err := ldapService.Connect(ldapConfig)
if err != nil {
    return err
}
defer conn.Close()

userDN := "CN=John Doe,OU=Users,DC=example,DC=com"
groups, err := ldapService.GetUserGroups(conn, ldapConfig, userDN)
if err != nil {
    log.Error("Failed to get user groups", zap.Error(err))
    return err
}

log.Info("User groups", zap.Strings("groups", groups))
```

## Configuration Details

### Connection Types

#### LDAPS (TLS)
```json
{
    "host": "ad.example.com",
    "port": 636,
    "use_tls": true,
    "use_start_tls": false,
    "skip_tls_verify": false,
    "server_name": "ad.example.com"
}
```

#### LDAP with StartTLS
```json
{
    "host": "ad.example.com",
    "port": 389,
    "use_tls": false,
    "use_start_tls": true,
    "skip_tls_verify": false,
    "server_name": "ad.example.com"
}
```

#### Plain LDAP (Not Recommended)
```json
{
    "host": "ad.example.com",
    "port": 389,
    "use_tls": false,
    "use_start_tls": false
}
```

### Common User Filters

#### By sAMAccountName
```
(&(objectClass=user)(sAMAccountName=%s))
```

#### By userPrincipalName
```
(&(objectClass=user)(userPrincipalName=%s@example.com))
```

#### Active Users Only
```
(&(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

### Common Group Filters

#### By Member DN
```
(&(objectClass=group)(member=%s))
```

#### Security Groups Only
```
(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(member=%s))
```

## Integration with Auth Flow

Update the `AuthService.Login` method to use the LDAP service:

```go
// In AuthService
func (s *AuthService) Login(ctx context.Context, req *models.LoginRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
    tenantID, _ := uuid.Parse(req.TenantID)

    // First try local authentication
    user, err := s.authenticateLocal(ctx, tenantID, req.Username, req.Password)

    if err != nil {
        // Try LDAP authentication
        // Get LDAP providers for tenant
        providers, err := s.idpRepo.GetByTenantAndType(ctx, tenantID, "ldap")
        if err == nil && len(providers) > 0 {
            // Try each provider in priority order
            for _, provider := range providers {
                user, err = s.ldapService.Authenticate(ctx, tenantID, provider.ID, req.Username, req.Password)
                if err == nil {
                    break // Authentication successful
                }
                logger.Debug("LDAP auth failed, trying next provider",
                    zap.String("provider", provider.Name),
                    zap.Error(err),
                )
            }
        }

        if user == nil || err != nil {
            s.auditService.LogLogin(ctx, tenantID, nil, ipAddress, userAgent, false, "authentication failed")
            return nil, fmt.Errorf("authentication failed")
        }
    }

    // Continue with token generation...
}
```

## Database Schema

The LDAP service requires the `iam_identity_providers` table:

```sql
CREATE TABLE iam_identity_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- 'ldap', 'saml', 'oauth', 'oidc'
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,
    priority INTEGER DEFAULT 0,
    config JSONB NOT NULL, -- Provider-specific configuration
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES iam_users(id),
    updated_by UUID REFERENCES iam_users(id),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_identity_providers_tenant ON iam_identity_providers(tenant_id);
CREATE INDEX idx_identity_providers_type ON iam_identity_providers(type);
CREATE INDEX idx_identity_providers_active ON iam_identity_providers(is_active);
```

## Scheduled Sync

For periodic synchronization, create a scheduled job:

```go
func (s *LDAPService) StartSyncScheduler(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            s.syncAllProviders(ctx)
        case <-ctx.Done():
            return
        }
    }
}

func (s *LDAPService) syncAllProviders(ctx context.Context) {
    // Get all active LDAP providers with sync enabled
    // This would require a new repository method
    providers, err := s.idpRepo.GetActiveSyncProviders(ctx, "ldap")
    if err != nil {
        logger.Error("Failed to get sync providers", zap.Error(err))
        return
    }

    for _, provider := range providers {
        ldapConfig, _ := s.parseLDAPConfig(provider.Config)
        if !ldapConfig.SyncEnabled {
            continue
        }

        // Check if sync is due
        lastSync := getLastSyncTime(provider.ID) // Implement this
        if time.Since(lastSync) < time.Duration(ldapConfig.SyncInterval)*time.Minute {
            continue
        }

        logger.Info("Starting scheduled LDAP sync", zap.String("provider", provider.Name))
        result, err := s.SyncUsers(ctx, provider.ID, false)
        if err != nil {
            logger.Error("Scheduled sync failed",
                zap.String("provider", provider.Name),
                zap.Error(err),
            )
        } else {
            logger.Info("Scheduled sync completed",
                zap.String("provider", provider.Name),
                zap.Int("users_created", result.UsersCreated),
                zap.Int("users_updated", result.UsersUpdated),
            )
        }
    }
}
```

## Error Handling

The LDAP service returns descriptive errors:

- Connection errors: `"failed to connect to LDAP: ..."`
- Authentication errors: `"invalid credentials"`
- Search errors: `"user search failed: ..."`
- Configuration errors: `"invalid LDAP configuration: ..."`

Always log errors with appropriate context for debugging.

## Security Considerations

1. **Credentials Storage**: The `bind_password` should be encrypted in the database
2. **TLS**: Always use TLS or StartTLS in production
3. **Certificate Validation**: Set `skip_tls_verify: false` in production
4. **Service Account**: Use a dedicated service account with minimal permissions
5. **Rate Limiting**: Implement rate limiting for authentication attempts
6. **Audit Logging**: All authentication attempts are logged for security auditing

## Performance Tips

1. Use connection pooling for high-volume environments
2. Cache LDAP configurations to reduce database queries
3. Implement incremental sync instead of full sync when possible
4. Use indexed attributes in LDAP filters
5. Limit sync scope with appropriate search bases

## Troubleshooting

### Connection Issues
- Verify network connectivity to LDAP server
- Check firewall rules (port 389 for LDAP, 636 for LDAPS)
- Verify bind credentials
- Check TLS certificate validity

### Search Issues
- Verify base DN is correct
- Check search filter syntax
- Ensure service account has read permissions
- Verify attribute names match your AD schema

### Authentication Issues
- Check user exists in LDAP
- Verify user filter matches username format
- Ensure user account is enabled in AD
- Check password policies

### Sync Issues
- Review sync result errors
- Check attribute mappings
- Verify group mappings are correct
- Ensure role names exist in database
