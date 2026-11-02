// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ============================================================================
// Active Directory Operations
// ============================================================================

// getFirstLDAPProvider returns the first active LDAP identity provider for HR operations.
// SECURITY: This function now returns nil if no provider is explicitly configured.
// No default tenant fallback - requires explicit identity provider configuration.
func (s *LDAPService) getFirstLDAPProvider(ctx context.Context) *models.IdentityProvider {
	if s.idpRepo == nil {
		logger.Warn("LDAP identity provider repository not configured")
		return nil
	}

	providers, err := s.idpRepo.GetAllByType(ctx, federationTypeLDAP)
	if err != nil {
		logger.Error("Failed to get LDAP providers", zap.Error(err))
		return nil
	}

	for _, provider := range providers {
		if provider.IsEnabled {
			return provider
		}
	}

	logger.Warn("No active LDAP identity providers configured - LDAP operations will fail")
	return nil
}

// connectToAD creates a connection to AD using settings from a configured identity provider.
// SECURITY: Delegates to s.Connect() which handles encrypted password decryption and TLS enforcement.
func (s *LDAPService) connectToAD(ctx context.Context) (*ldap.Conn, error) {
	provider := s.getFirstLDAPProvider(ctx)
	if provider == nil {
		return nil, fmt.Errorf("no LDAP identity provider configured - AD operations require explicit identity provider setup")
	}

	if provider.LDAPConfig == nil {
		return nil, fmt.Errorf("LDAP identity provider %s has no LDAP configuration", provider.Name)
	}

	ldapConfig := provider.LDAPConfig

	if ldapConfig.Host == "" {
		return nil, fmt.Errorf("LDAP host not configured in identity provider %s", provider.Name)
	}
	if ldapConfig.BindDN == "" {
		return nil, fmt.Errorf("LDAP bind DN not configured in identity provider %s", provider.Name)
	}
	// Check for either plaintext or encrypted bind password
	if ldapConfig.BindPassword == "" && ldapConfig.BindPasswordEncrypted == "" {
		return nil, fmt.Errorf("LDAP bind password not configured in identity provider %s", provider.Name)
	}

	// Default port if not set
	if ldapConfig.Port == 0 {
		if ldapConfig.UseTLS {
			ldapConfig.Port = 636
		} else {
			ldapConfig.Port = 389
		}
	}

	// Delegate to s.Connect() which handles TLS enforcement and encrypted password decryption
	conn, err := s.Connect(ldapConfig)
	if err != nil {
		return nil, fmt.Errorf("connectToAD: %w", err)
	}

	logger.Debug("Successfully connected to AD", zap.String("provider", provider.Name))
	return conn, nil
}

// getHRLDAPSettings returns LDAP settings for HR operations from identity provider.
// SECURITY: This function requires an explicitly configured identity provider.
func (s *LDAPService) getHRLDAPSettings(ctx context.Context) (baseDN, userFilter, groupBaseDN, groupFilter string, err error) {
	defaultUserFilter := "(&(objectClass=user)(objectCategory=person))"
	defaultGroupFilter := "(objectClass=group)"

	provider := s.getFirstLDAPProvider(ctx)
	if provider == nil {
		return "", "", "", "", fmt.Errorf("no LDAP identity provider configured - HR operations require explicit identity provider setup")
	}

	if provider.LDAPConfig == nil {
		return "", "", "", "", fmt.Errorf("LDAP identity provider %s has no LDAP configuration", provider.Name)
	}

	ldapConfig := provider.LDAPConfig

	if ldapConfig.BaseDN == "" {
		return "", "", "", "", fmt.Errorf("LDAP base DN not configured in identity provider %s", provider.Name)
	}

	baseDN = ldapConfig.UserSearchBase
	if baseDN == "" {
		baseDN = ldapConfig.BaseDN
	}

	groupBaseDN = ldapConfig.GroupSearchBase
	if groupBaseDN == "" {
		groupBaseDN = ldapConfig.BaseDN
	}

	groupFilter = ldapConfig.GroupFilter
	if groupFilter == "" || strings.Contains(groupFilter, "%s") {
		groupFilter = defaultGroupFilter
	}

	userFilter = ldapConfig.UserFilter
	if userFilter == "" || strings.Contains(userFilter, "%s") {
		userFilter = defaultUserFilter
	}

	return baseDN, userFilter, groupBaseDN, groupFilter, nil
}

// GetEmployees returns all employees from Active Directory.
func (s *LDAPService) GetEmployees(ctx context.Context) ([]models.ADUser, error) {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetEmployees: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	baseDN, userFilter, _, _, err := s.getHRLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetEmployees: settings: %w", err)
	}

	logger.Info("GetEmployees using settings",
		zap.String("base_dn", baseDN),
		zap.String("user_filter", userFilter),
	)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		userFilter,
		[]string{
			"dn", "sAMAccountName", "userPrincipalName", "mail", "givenName", "sn",
			"displayName", "department", "title", "telephoneNumber", "memberOf", "userAccountControl",
		},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("GetEmployees: search failed: %w", err)
	}

	logger.Info("LDAP search completed", zap.Int("entries_found", len(result.Entries)))

	return mapLDAPEntriesToEmployees(result.Entries), nil
}

// mapLDAPEntriesToEmployees converts LDAP entries to ADUser models
func mapLDAPEntriesToEmployees(entries []*ldap.Entry) []models.ADUser {
	var employees []models.ADUser
	for _, entry := range entries {
		uac := entry.GetAttributeValue("userAccountControl")
		enabled := true
		if uac != "" {
			var uacInt int
			_, _ = fmt.Sscanf(uac, "%d", &uacInt)
			enabled = (uacInt & 0x2) == 0
		}

		employees = append(employees, models.ADUser{
			DN:                entry.DN,
			SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
			UserPrincipalName: entry.GetAttributeValue("userPrincipalName"),
			Email:             entry.GetAttributeValue("mail"),
			FirstName:         entry.GetAttributeValue("givenName"),
			LastName:          entry.GetAttributeValue("sn"),
			DisplayName:       entry.GetAttributeValue("displayName"),
			Department:        entry.GetAttributeValue("department"),
			Title:             entry.GetAttributeValue("title"),
			Phone:             entry.GetAttributeValue("telephoneNumber"),
			MemberOf:          entry.GetAttributeValues("memberOf"),
			Enabled:           enabled,
		})
	}
	return employees
}

// GetGroups returns all groups from Active Directory.
func (s *LDAPService) GetGroups(ctx context.Context) ([]models.ADGroup, error) {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetGroups: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	_, _, groupBaseDN, groupFilter, err := s.getHRLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetGroups: settings: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		groupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		groupFilter,
		[]string{"dn", "cn", "description", "member"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("GetGroups: search failed: %w", err)
	}

	var groups []models.ADGroup
	for _, entry := range result.Entries {
		groups = append(groups, models.ADGroup{
			DN:          entry.DN,
			Name:        entry.GetAttributeValue("cn"),
			Description: entry.GetAttributeValue("description"),
			Members:     entry.GetAttributeValues("member"),
		})
	}

	return groups, nil
}

// SyncGroups synchronizes groups from LDAP to the local database
func (s *LDAPService) SyncGroups(ctx context.Context, providerID uuid.UUID, tenantID uuid.UUID) (created, updated int, err error) {
	if s.groupRepo == nil {
		return 0, 0, fmt.Errorf("SyncGroups: group repository not configured")
	}

	ldapGroups, err := s.GetGroups(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("SyncGroups: %w", err)
	}

	logger.Info("Syncing LDAP groups", zap.Int("groups_found", len(ldapGroups)))

	for _, ldapGroup := range ldapGroups {
		existingGroup, _ := s.groupRepo.GetByName(ctx, tenantID, ldapGroup.Name)

		now := time.Now()
		description := ldapGroup.Description
		metadata := map[string]interface{}{
			"ldap_dn":      ldapGroup.DN,
			"ldap_source":  federationTypeLDAP,
			"provider_id":  providerID.String(),
			"member_count": len(ldapGroup.Members),
		}

		if existingGroup != nil {
			existingGroup.DisplayName = &ldapGroup.Name
			existingGroup.Description = &description
			existingGroup.UpdatedAt = now
			existingGroup.Metadata = metadata
			if updateErr := s.groupRepo.Update(ctx, existingGroup); updateErr != nil {
				logger.Warn("Failed to update group", zap.String("name", ldapGroup.Name), zap.Error(updateErr))
			} else {
				updated++
			}
			continue
		}
		newGroup := &models.Group{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Name:        ldapGroup.Name,
			DisplayName: &ldapGroup.Name,
			Description: &description,
			IsSystem:    false,
			CreatedAt:   now,
			UpdatedAt:   now,
			Metadata:    metadata,
		}
		if createErr := s.groupRepo.Create(ctx, newGroup); createErr != nil {
			logger.Warn("Failed to create group", zap.String("name", ldapGroup.Name), zap.Error(createErr))
		} else {
			created++
		}
	}

	logger.Info("LDAP group sync completed", zap.Int("created", created), zap.Int("updated", updated))
	return created, updated, nil
}

// CreateEmployee creates a new employee in Active Directory.
func (s *LDAPService) CreateEmployee(ctx context.Context, req *models.CreateEmployeeRequest) (*models.ADUser, error) {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return nil, fmt.Errorf("CreateEmployee: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	baseDN, _, _, _, err := s.getHRLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("CreateEmployee: settings: %w", err)
	}

	provider := s.getFirstLDAPProvider(ctx)
	if provider == nil || provider.LDAPConfig == nil {
		return nil, fmt.Errorf("CreateEmployee: no LDAP identity provider configured")
	}

	domain := extractDomainFromBaseDN(provider.LDAPConfig.BaseDN)
	if domain == "" {
		return nil, fmt.Errorf("CreateEmployee: could not determine domain from LDAP base DN")
	}

	userDN := fmt.Sprintf("CN=%s %s,%s", escapeDNValue(req.FirstName), escapeDNValue(req.LastName), baseDN)
	upn := fmt.Sprintf("%s@%s", req.Username, domain)

	addReq := ldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addReq.Attribute("sAMAccountName", []string{req.Username})
	addReq.Attribute("userPrincipalName", []string{upn})
	addReq.Attribute("givenName", []string{req.FirstName})
	addReq.Attribute("sn", []string{req.LastName})
	addReq.Attribute("displayName", []string{fmt.Sprintf("%s %s", req.FirstName, req.LastName)})
	addReq.Attribute("mail", []string{req.Email})
	addReq.Attribute("userAccountControl", []string{"544"})

	if req.Department != "" {
		addReq.Attribute("department", []string{req.Department})
	}
	if req.Title != "" {
		addReq.Attribute("title", []string{req.Title})
	}

	if err := conn.Add(addReq); err != nil {
		return nil, fmt.Errorf("CreateEmployee: add failed: %w", err)
	}

	passwordReq := ldap.NewModifyRequest(userDN, nil)
	encodedPassword := encodeADPassword(req.Password)
	passwordReq.Replace("unicodePwd", []string{encodedPassword})
	passwordReq.Replace("userAccountControl", []string{"512"})

	if err := conn.Modify(passwordReq); err != nil {
		_ = conn.Del(ldap.NewDelRequest(userDN, nil))
		return nil, fmt.Errorf("CreateEmployee: set password failed: %w", err)
	}

	return &models.ADUser{
		DN:                userDN,
		SAMAccountName:    req.Username,
		UserPrincipalName: upn,
		Email:             req.Email,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		DisplayName:       fmt.Sprintf("%s %s", req.FirstName, req.LastName),
		Department:        req.Department,
		Title:             req.Title,
		Enabled:           true,
	}, nil
}

// UpdateEmployee updates an existing employee in Active Directory
func (s *LDAPService) UpdateEmployee(ctx context.Context, req *models.UpdateEmployeeRequest) error {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return fmt.Errorf("UpdateEmployee: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	modifyReq := ldap.NewModifyRequest(req.UserDN, nil)
	hasChanges := false

	if req.Email != nil && *req.Email != "" {
		modifyReq.Replace("mail", []string{*req.Email})
		hasChanges = true
	}
	if req.FirstName != nil && *req.FirstName != "" {
		modifyReq.Replace("givenName", []string{*req.FirstName})
		hasChanges = true
	}
	if req.LastName != nil && *req.LastName != "" {
		modifyReq.Replace("sn", []string{*req.LastName})
		hasChanges = true
	}
	if req.Department != nil {
		if *req.Department != "" {
			modifyReq.Replace("department", []string{*req.Department})
		} else {
			modifyReq.Delete("department", []string{})
		}
		hasChanges = true
	}
	if req.Title != nil {
		if *req.Title != "" {
			modifyReq.Replace("title", []string{*req.Title})
		} else {
			modifyReq.Delete("title", []string{})
		}
		hasChanges = true
	}
	if req.Phone != nil {
		if *req.Phone != "" {
			modifyReq.Replace("telephoneNumber", []string{*req.Phone})
		} else {
			modifyReq.Delete("telephoneNumber", []string{})
		}
		hasChanges = true
	}

	if !hasChanges {
		return nil
	}

	if err := conn.Modify(modifyReq); err != nil {
		return fmt.Errorf("UpdateEmployee: modify failed: %w", err)
	}

	return nil
}

// DeleteEmployee deletes an employee from Active Directory
func (s *LDAPService) DeleteEmployee(ctx context.Context, userDN string) error {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return fmt.Errorf("DeleteEmployee: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	if err := conn.Del(ldap.NewDelRequest(userDN, nil)); err != nil {
		return fmt.Errorf("DeleteEmployee: %w", err)
	}

	return nil
}

// ResetPassword resets an employee's password in Active Directory
func (s *LDAPService) ResetPassword(ctx context.Context, req *models.ResetPasswordRequest) error {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return fmt.Errorf("ResetPassword: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	modifyReq := ldap.NewModifyRequest(req.UserDN, nil)
	modifyReq.Replace("unicodePwd", []string{encodeADPassword(req.NewPassword)})

	if req.MustChangePassword {
		modifyReq.Replace("pwdLastSet", []string{"0"})
	}

	if err := conn.Modify(modifyReq); err != nil {
		return fmt.Errorf("ResetPassword: %w", err)
	}

	return nil
}

// EnableEmployee enables an employee account in Active Directory
func (s *LDAPService) EnableEmployee(ctx context.Context, userDN string) error {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return fmt.Errorf("EnableEmployee: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	modifyReq := ldap.NewModifyRequest(userDN, nil)
	modifyReq.Replace("userAccountControl", []string{"512"})

	if err := conn.Modify(modifyReq); err != nil {
		return fmt.Errorf("EnableEmployee: %w", err)
	}

	return nil
}

// DisableEmployee disables an employee account in Active Directory
func (s *LDAPService) DisableEmployee(ctx context.Context, userDN string) error {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return fmt.Errorf("DisableEmployee: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	modifyReq := ldap.NewModifyRequest(userDN, nil)
	modifyReq.Replace("userAccountControl", []string{"514"})

	if err := conn.Modify(modifyReq); err != nil {
		return fmt.Errorf("DisableEmployee: %w", err)
	}

	return nil
}

// AddUserToGroup adds a user to an Active Directory group
func (s *LDAPService) AddUserToGroup(ctx context.Context, userDN, groupDN string) error {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return fmt.Errorf("AddUserToGroup: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	modifyReq := ldap.NewModifyRequest(groupDN, nil)
	modifyReq.Add("member", []string{userDN})

	if err := conn.Modify(modifyReq); err != nil {
		return fmt.Errorf("AddUserToGroup: %w", err)
	}

	return nil
}

// RemoveUserFromGroup removes a user from an Active Directory group
func (s *LDAPService) RemoveUserFromGroup(ctx context.Context, userDN, groupDN string) error {
	conn, err := s.connectToAD(ctx)
	if err != nil {
		return fmt.Errorf("RemoveUserFromGroup: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	modifyReq := ldap.NewModifyRequest(groupDN, nil)
	modifyReq.Delete("member", []string{userDN})

	if err := conn.Modify(modifyReq); err != nil {
		return fmt.Errorf("RemoveUserFromGroup: %w", err)
	}

	return nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// escapeDNValue escapes special characters in an LDAP DN attribute value per
// RFC 4514 §2.4.  This prevents LDAP injection when constructing DNs from
// user-supplied input (e.g. first/last name fields).
//
// Characters escaped: \ , + " < > ; =
// Leading/trailing spaces and a leading # are also escaped.
func escapeDNValue(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`,`, `\,`,
		`+`, `\+`,
		`"`, `\"`,
		`<`, `\<`,
		`>`, `\>`,
		`;`, `\;`,
		`=`, `\=`,
	)
	s = replacer.Replace(s)

	// Leading/trailing space must be escaped.
	if len(s) > 0 && s[0] == ' ' {
		s = `\ ` + s[1:]
	}
	if len(s) > 1 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1] + `\ `
	}

	// A leading '#' must be escaped (RFC 4514 §2.4).
	if len(s) > 0 && s[0] == '#' {
		s = `\#` + s[1:]
	}

	return s
}

// encodeADPassword encodes a password for Active Directory unicodePwd attribute
func encodeADPassword(password string) string {
	quotedPassword := "\"" + password + "\""
	runes := []rune(quotedPassword)
	utf16le := make([]byte, len(runes)*2)
	for i, r := range runes {
		utf16le[i*2] = byte(r)        //nolint:gosec // rune is always ASCII in this context, safe conversion
		utf16le[i*2+1] = byte(r >> 8) //nolint:gosec // rune is always ASCII in this context, safe conversion
	}
	return string(utf16le)
}

// extractDomainFromBaseDN extracts a domain name from a BaseDN.
// e.g., "DC=example,DC=corp" -> "example.corp"
func extractDomainFromBaseDN(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	var domainParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			dcValue := strings.TrimPrefix(part, "DC=")
			dcValue = strings.TrimPrefix(dcValue, "dc=")
			domainParts = append(domainParts, dcValue)
		}
	}

	if len(domainParts) == 0 {
		return ""
	}

	return strings.Join(domainParts, ".")
}
