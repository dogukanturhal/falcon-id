// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"
)

// ADUser represents a user from Active Directory
type ADUser struct {
	DN                string            `json:"dn"`
	SAMAccountName    string            `json:"sam_account_name"`
	UserPrincipalName string            `json:"user_principal_name"`
	Email             string            `json:"email"`
	FirstName         string            `json:"first_name"`
	LastName          string            `json:"last_name"`
	DisplayName       string            `json:"display_name"`
	Department        string            `json:"department,omitempty"`
	Title             string            `json:"title,omitempty"`
	Phone             string            `json:"phone,omitempty"`
	Manager           string            `json:"manager,omitempty"`
	MemberOf          []string          `json:"member_of"`
	Enabled           bool              `json:"enabled"`
	ObjectGUID        string            `json:"object_guid"`
	WhenCreated       time.Time         `json:"when_created"`
	WhenChanged       time.Time         `json:"when_changed"`
	Attributes        map[string]string `json:"attributes,omitempty"`
}

// ADGroup represents a group from Active Directory
type ADGroup struct {
	DN          string   `json:"dn"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
	ObjectGUID  string   `json:"object_guid"`
}

// CreateEmployeeRequest represents a request to create an employee
type CreateEmployeeRequest struct {
	Username   string   `json:"username" binding:"required,min=2,max=50"`
	Password   string   `json:"password" binding:"required,min=8"`
	Email      string   `json:"email" binding:"required,email"`
	FirstName  string   `json:"first_name" binding:"required"`
	LastName   string   `json:"last_name" binding:"required"`
	Department string   `json:"department,omitempty"`
	Title      string   `json:"title,omitempty"`
	Groups     []string `json:"groups,omitempty"`
}

// UpdateEmployeeRequest represents a request to update an employee
type UpdateEmployeeRequest struct {
	UserDN     string  `json:"user_dn" binding:"required"`
	Email      *string `json:"email,omitempty"`
	FirstName  *string `json:"first_name,omitempty"`
	LastName   *string `json:"last_name,omitempty"`
	Department *string `json:"department,omitempty"`
	Title      *string `json:"title,omitempty"`
	Phone      *string `json:"phone,omitempty"`
}

// ResetPasswordRequest represents a request to reset a user's password
type ResetPasswordRequest struct {
	UserDN             string `json:"user_dn" binding:"required"`
	NewPassword        string `json:"new_password" binding:"required,min=8"`
	MustChangePassword bool   `json:"must_change_password"`
}

// AccountStatusRequest represents a request to enable/disable an account
type AccountStatusRequest struct {
	UserDN  string `json:"user_dn" binding:"required"`
	Enabled bool   `json:"enabled"`
}

// DeleteEmployeeRequest represents a request to delete an employee
type DeleteEmployeeRequest struct {
	UserDN string `json:"user_dn" binding:"required"`
}

// GroupMembershipRequest represents a request to add/remove user from group
type GroupMembershipRequest struct {
	UserDN  string `json:"user_dn" binding:"required"`
	GroupDN string `json:"group_dn" binding:"required"`
}

// EmployeeListResponse represents the employees list response
type EmployeeListResponse struct {
	Employees []ADUser `json:"employees"`
	Total     int      `json:"total"`
}

// GroupListResponse represents the groups list response
type GroupListResponse struct {
	Groups []ADGroup `json:"groups"`
	Total  int       `json:"total"`
}
