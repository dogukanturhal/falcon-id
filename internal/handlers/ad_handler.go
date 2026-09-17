// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgInvalidRequest       = "Invalid request"
	msgInvalidRequestPrefix = "Invalid request: "
)

// ADHandler handles Active Directory employee management requests
type ADHandler struct {
	ldapService *services.LDAPService
	logger      *zap.Logger
}

// NewADHandler creates a new AD handler
func NewADHandler(ldapService *services.LDAPService, logger *zap.Logger) *ADHandler {
	return &ADHandler{
		ldapService: ldapService,
		logger:      logger,
	}
}

// ListEmployees returns all employees from AD
// @Summary List employees
// @Description Get all employees from Active Directory
// @Tags employees
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.EmployeeListResponse
// @Failure 500 {object} map[string]string
// @Router /api/employees [get]
func (h *ADHandler) ListEmployees(c *gin.Context) {
	employees, err := h.ldapService.GetEmployees(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to get employees", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch employees"})
		return
	}

	c.JSON(http.StatusOK, models.EmployeeListResponse{
		Employees: employees,
		Total:     len(employees),
	})
}

// CreateEmployee creates a new employee in AD
// @Summary Create employee
// @Description Create a new employee in Active Directory
// @Tags employees
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.CreateEmployeeRequest true "Employee details"
// @Success 201 {object} models.ADUser
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/employees [post]
func (h *ADHandler) CreateEmployee(c *gin.Context) {
	var req models.CreateEmployeeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error(msgInvalidRequest, zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestPrefix + err.Error()})
		return
	}

	h.logger.Info("Creating employee", zap.String("username", req.Username))

	user, err := h.ldapService.CreateEmployee(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to create employee", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create employee"})
		return
	}

	h.logger.Info("Employee created successfully", zap.String("username", req.Username), zap.String("dn", user.DN))

	c.JSON(http.StatusCreated, user)
}

// UpdateEmployee updates an existing employee
// @Summary Update employee
// @Description Update an existing employee in Active Directory
// @Tags employees
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.UpdateEmployeeRequest true "Employee update details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/employees [put]
func (h *ADHandler) UpdateEmployee(c *gin.Context) {
	var req models.UpdateEmployeeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error(msgInvalidRequest, zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestPrefix + err.Error()})
		return
	}

	h.logger.Info("Updating employee", zap.String("user_dn", req.UserDN))

	if err := h.ldapService.UpdateEmployee(c.Request.Context(), &req); err != nil {
		h.logger.Error("Failed to update employee", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update employee"})
		return
	}

	h.logger.Info("Employee updated successfully", zap.String("user_dn", req.UserDN))

	c.JSON(http.StatusOK, gin.H{"message": "Employee updated successfully"})
}

// DeleteEmployee deletes an employee from AD
// @Summary Delete employee
// @Description Delete an employee from Active Directory
// @Tags employees
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.DeleteEmployeeRequest true "Delete details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/employees [delete]
func (h *ADHandler) DeleteEmployee(c *gin.Context) {
	var req models.DeleteEmployeeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error(msgInvalidRequest, zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestPrefix + err.Error()})
		return
	}

	h.logger.Info("Deleting employee", zap.String("user_dn", req.UserDN))

	if err := h.ldapService.DeleteEmployee(c.Request.Context(), req.UserDN); err != nil {
		h.logger.Error("Failed to delete employee", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete employee"})
		return
	}

	h.logger.Info("Employee deleted successfully", zap.String("user_dn", req.UserDN))

	c.JSON(http.StatusOK, gin.H{"message": "Employee deleted successfully"})
}

// ResetPassword resets an employee's password
// @Summary Reset password
// @Description Reset an employee's password in Active Directory
// @Tags employees
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.ResetPasswordRequest true "Password reset details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/employees/password [post]
func (h *ADHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error(msgInvalidRequest, zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestPrefix + err.Error()})
		return
	}

	h.logger.Info("Resetting password for user", zap.String("user_dn", req.UserDN))

	if err := h.ldapService.ResetPassword(c.Request.Context(), &req); err != nil {
		h.logger.Error("Failed to reset password", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	h.logger.Info("Password reset successfully", zap.String("user_dn", req.UserDN))

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// SetAccountStatus enables or disables an employee account
// @Summary Set account status
// @Description Enable or disable an employee account in Active Directory
// @Tags employees
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.AccountStatusRequest true "Account status details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/employees/status [post]
func (h *ADHandler) SetAccountStatus(c *gin.Context) {
	var req models.AccountStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error(msgInvalidRequest, zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestPrefix + err.Error()})
		return
	}

	h.logger.Info("Setting account status", zap.String("user_dn", req.UserDN), zap.Bool("enabled", req.Enabled))

	var err error
	if req.Enabled {
		err = h.ldapService.EnableEmployee(c.Request.Context(), req.UserDN)
	} else {
		err = h.ldapService.DisableEmployee(c.Request.Context(), req.UserDN)
	}

	if err != nil {
		h.logger.Error("Failed to set account status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set account status"})
		return
	}

	status := "disabled"
	if req.Enabled {
		status = "enabled"
	}
	h.logger.Info("Account status updated", zap.String("user_dn", req.UserDN), zap.String("status", status))

	c.JSON(http.StatusOK, gin.H{"message": "Account " + status + " successfully"})
}

// ListGroups returns all groups from AD
// @Summary List groups
// @Description Get all groups from Active Directory SSO OU
// @Tags groups
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.GroupListResponse
// @Failure 500 {object} map[string]string
// @Router /api/groups [get]
func (h *ADHandler) ListGroups(c *gin.Context) {
	groups, err := h.ldapService.GetGroups(c.Request.Context())
	if err != nil {
		// Degrade gracefully when no LDAP provider is configured
		if strings.Contains(err.Error(), "no LDAP identity provider configured") {
			c.JSON(http.StatusOK, models.GroupListResponse{Groups: nil, Total: 0})
			return
		}
		h.logger.Error("Failed to get groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups"})
		return
	}

	c.JSON(http.StatusOK, models.GroupListResponse{
		Groups: groups,
		Total:  len(groups),
	})
}

// AddUserToGroup adds a user to a group
// @Summary Add user to group
// @Description Add a user to an Active Directory group
// @Tags groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.GroupMembershipRequest true "Membership details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/groups/members [post]
func (h *ADHandler) AddUserToGroup(c *gin.Context) {
	var req models.GroupMembershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error(msgInvalidRequest, zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestPrefix + err.Error()})
		return
	}

	h.logger.Info("Adding user to group", zap.String("user_dn", req.UserDN), zap.String("group_dn", req.GroupDN))

	if err := h.ldapService.AddUserToGroup(c.Request.Context(), req.UserDN, req.GroupDN); err != nil {
		h.logger.Error("Failed to add user to group", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to group"})
		return
	}

	h.logger.Info("User added to group successfully", zap.String("user_dn", req.UserDN), zap.String("group_dn", req.GroupDN))

	c.JSON(http.StatusOK, gin.H{"message": "User added to group successfully"})
}

// RemoveUserFromGroup removes a user from a group
// @Summary Remove user from group
// @Description Remove a user from an Active Directory group
// @Tags groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.GroupMembershipRequest true "Membership details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/groups/members [delete]
func (h *ADHandler) RemoveUserFromGroup(c *gin.Context) {
	var req models.GroupMembershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error(msgInvalidRequest, zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestPrefix + err.Error()})
		return
	}

	h.logger.Info("Removing user from group", zap.String("user_dn", req.UserDN), zap.String("group_dn", req.GroupDN))

	if err := h.ldapService.RemoveUserFromGroup(c.Request.Context(), req.UserDN, req.GroupDN); err != nil {
		h.logger.Error("Failed to remove user from group", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from group"})
		return
	}

	h.logger.Info("User removed from group successfully", zap.String("user_dn", req.UserDN), zap.String("group_dn", req.GroupDN))

	c.JSON(http.StatusOK, gin.H{"message": "User removed from group successfully"})
}
