// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// scim_service_bulk.go — Bulk operations (RFC 7644 §3.7) and POST Search
// (RFC 7644 §3.4.3) for SCIMService.
//
// ExecuteBulk processes an array of SCIM operations sequentially.  Each
// operation is dispatched to the existing single-resource service methods so
// that validation, audit, and tracing logic is reused.
//
// Search delegates to the shared filter helpers already used by ListUsers /
// ListGroups; it adds the capability to specify pagination and filter via a
// JSON request body rather than query-string parameters.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ==================== Bulk Operations ====================

// ExecuteBulk processes a SCIMBulkRequest and returns a SCIMBulkResponse.
//
// Operations are executed sequentially.  When failOnErrors is set and the
// number of operation errors reaches that threshold, processing stops and the
// partial response is returned (per RFC 7644 §3.7).
func (s *SCIMService) ExecuteBulk(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.SCIMBulkRequest,
) (*models.SCIMBulkResponse, error) {
	if len(req.Operations) > models.SCIMMaxBulkOperations {
		return nil, fmt.Errorf(
			"ExecuteBulk: request contains %d operations which exceeds the maximum of %d",
			len(req.Operations),
			models.SCIMMaxBulkOperations,
		)
	}

	// failOnErrors defaults to "no limit" (0 means process all).
	failThreshold := 0
	if req.FailOnErrors != nil {
		failThreshold = *req.FailOnErrors
	}

	results := make([]models.SCIMBulkOperationResult, 0, len(req.Operations))
	errorCount := 0

	for _, op := range req.Operations {
		result := s.executeBulkOperation(ctx, tenantID, op)
		results = append(results, result)

		statusCode, _ := strconv.Atoi(result.Status)
		if statusCode >= http.StatusBadRequest {
			errorCount++
			if failThreshold > 0 && errorCount >= failThreshold {
				break
			}
		}
	}

	return &models.SCIMBulkResponse{
		Schemas:    []string{models.SCIMSchemaBulkResponse},
		Operations: results,
	}, nil
}

// executeBulkOperation dispatches a single BulkOperation to the appropriate
// service method and converts the outcome into a SCIMBulkOperationResult.
func (s *SCIMService) executeBulkOperation(
	ctx context.Context,
	tenantID uuid.UUID,
	op models.SCIMBulkOperation,
) models.SCIMBulkOperationResult {
	method := strings.ToUpper(op.Method)

	result := models.SCIMBulkOperationResult{
		Method: method,
		BulkID: op.BulkID,
	}

	// Determine resource type and optional resource ID from the path.
	// Expected path forms: "/Users", "/Users/<id>", "/Groups", "/Groups/<id>".
	resourceType, resourceID, parseErr := parseBulkPath(op.Path)
	if parseErr != nil {
		result.Status = strconv.Itoa(http.StatusBadRequest)
		result.Response = models.SCIMError{
			Schemas:  []string{models.SCIMSchemaError},
			Status:   strconv.Itoa(http.StatusBadRequest),
			ScimType: "invalidPath",
			Detail:   parseErr.Error(),
		}
		return result
	}

	switch resourceType {
	case "Users":
		return s.executeBulkUserOp(ctx, tenantID, method, resourceID, op, result)
	case "Groups":
		return s.executeBulkGroupOp(ctx, tenantID, method, resourceID, op, result)
	default:
		result.Status = strconv.Itoa(http.StatusBadRequest)
		result.Response = models.SCIMError{
			Schemas:  []string{models.SCIMSchemaError},
			Status:   strconv.Itoa(http.StatusBadRequest),
			ScimType: "invalidPath",
			Detail:   fmt.Sprintf("unsupported resource type %q", resourceType),
		}
		return result
	}
}

func (s *SCIMService) executeBulkUserOp(
	ctx context.Context,
	tenantID uuid.UUID,
	method string,
	resourceID string,
	op models.SCIMBulkOperation,
	result models.SCIMBulkOperationResult,
) models.SCIMBulkOperationResult {
	baseURL := s.getBaseURL()

	switch method {
	case http.MethodPost:
		scimUser, err := decodeBulkData[models.SCIMUser](op.Data)
		if err != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", "invalid user data: "+err.Error())
		}
		created, err := s.CreateUser(ctx, tenantID, scimUser)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "already exists") {
				return bulkError(result, http.StatusConflict, "uniqueness", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusCreated)
		result.Location = baseURL + "/scim/v2/Users/" + created.ID
		if created.Meta != nil {
			result.Version = created.Meta.Version
		}
		result.Response = created
		return result

	case http.MethodPut:
		id, parseErr := parseResourceID(resourceID)
		if parseErr != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", parseErr.Error())
		}
		if err := s.ValidateUserTenant(ctx, id, tenantID); err != nil {
			return bulkError(result, http.StatusNotFound, "noTarget", "user not found")
		}
		scimUser, err := decodeBulkData[models.SCIMUser](op.Data)
		if err != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", "invalid user data: "+err.Error())
		}
		updated, err := s.UpdateUser(ctx, id, scimUser)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return bulkError(result, http.StatusNotFound, "noTarget", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusOK)
		result.Location = baseURL + "/scim/v2/Users/" + updated.ID
		if updated.Meta != nil {
			result.Version = updated.Meta.Version
		}
		result.Response = updated
		return result

	case http.MethodPatch:
		id, parseErr := parseResourceID(resourceID)
		if parseErr != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", parseErr.Error())
		}
		if err := s.ValidateUserTenant(ctx, id, tenantID); err != nil {
			return bulkError(result, http.StatusNotFound, "noTarget", "user not found")
		}
		patchOp, err := decodeBulkData[models.SCIMPatchOp](op.Data)
		if err != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", "invalid patch data: "+err.Error())
		}
		patched, err := s.PatchUser(ctx, id, patchOp)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return bulkError(result, http.StatusNotFound, "noTarget", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusOK)
		result.Location = baseURL + "/scim/v2/Users/" + patched.ID
		if patched.Meta != nil {
			result.Version = patched.Meta.Version
		}
		result.Response = patched
		return result

	case http.MethodDelete:
		id, parseErr := parseResourceID(resourceID)
		if parseErr != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", parseErr.Error())
		}
		if err := s.ValidateUserTenant(ctx, id, tenantID); err != nil {
			return bulkError(result, http.StatusNotFound, "noTarget", "user not found")
		}
		if err := s.DeleteUser(ctx, id); err != nil {
			if strings.Contains(err.Error(), "not found") {
				return bulkError(result, http.StatusNotFound, "noTarget", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusNoContent)
		result.Location = baseURL + "/scim/v2/Users/" + resourceID
		return result

	default:
		return bulkError(result, http.StatusBadRequest, "invalidValue", fmt.Sprintf("unsupported method %q for Users", method))
	}
}

func (s *SCIMService) executeBulkGroupOp(
	ctx context.Context,
	tenantID uuid.UUID,
	method string,
	resourceID string,
	op models.SCIMBulkOperation,
	result models.SCIMBulkOperationResult,
) models.SCIMBulkOperationResult {
	baseURL := s.getBaseURL()

	switch method {
	case http.MethodPost:
		scimGroup, err := decodeBulkData[models.SCIMGroup](op.Data)
		if err != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", "invalid group data: "+err.Error())
		}
		created, err := s.CreateGroup(ctx, tenantID, scimGroup)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "already exists") {
				return bulkError(result, http.StatusConflict, "uniqueness", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusCreated)
		result.Location = baseURL + "/scim/v2/Groups/" + created.ID
		if created.Meta != nil {
			result.Version = created.Meta.Version
		}
		result.Response = created
		return result

	case http.MethodPut:
		id, parseErr := parseResourceID(resourceID)
		if parseErr != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", parseErr.Error())
		}
		if err := s.ValidateGroupTenant(ctx, id, tenantID); err != nil {
			return bulkError(result, http.StatusNotFound, "noTarget", "group not found")
		}
		scimGroup, err := decodeBulkData[models.SCIMGroup](op.Data)
		if err != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", "invalid group data: "+err.Error())
		}
		updated, err := s.UpdateGroup(ctx, id, scimGroup)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return bulkError(result, http.StatusNotFound, "noTarget", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusOK)
		result.Location = baseURL + "/scim/v2/Groups/" + updated.ID
		if updated.Meta != nil {
			result.Version = updated.Meta.Version
		}
		result.Response = updated
		return result

	case http.MethodPatch:
		id, parseErr := parseResourceID(resourceID)
		if parseErr != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", parseErr.Error())
		}
		if err := s.ValidateGroupTenant(ctx, id, tenantID); err != nil {
			return bulkError(result, http.StatusNotFound, "noTarget", "group not found")
		}
		patchOp, err := decodeBulkData[models.SCIMPatchOp](op.Data)
		if err != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", "invalid patch data: "+err.Error())
		}
		patched, err := s.PatchGroup(ctx, id, patchOp)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return bulkError(result, http.StatusNotFound, "noTarget", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusOK)
		result.Location = baseURL + "/scim/v2/Groups/" + patched.ID
		if patched.Meta != nil {
			result.Version = patched.Meta.Version
		}
		result.Response = patched
		return result

	case http.MethodDelete:
		id, parseErr := parseResourceID(resourceID)
		if parseErr != nil {
			return bulkError(result, http.StatusBadRequest, "invalidValue", parseErr.Error())
		}
		if err := s.ValidateGroupTenant(ctx, id, tenantID); err != nil {
			return bulkError(result, http.StatusNotFound, "noTarget", "group not found")
		}
		if err := s.DeleteGroup(ctx, id); err != nil {
			if strings.Contains(err.Error(), "not found") {
				return bulkError(result, http.StatusNotFound, "noTarget", err.Error())
			}
			return bulkError(result, http.StatusInternalServerError, "", err.Error())
		}
		result.Status = strconv.Itoa(http.StatusNoContent)
		result.Location = baseURL + "/scim/v2/Groups/" + resourceID
		return result

	default:
		return bulkError(result, http.StatusBadRequest, "invalidValue", fmt.Sprintf("unsupported method %q for Groups", method))
	}
}

// ==================== POST Search ====================

// SearchUsers executes a POST .search against Users with the given search
// parameters, reusing the existing filter helpers.
func (s *SCIMService) SearchUsers(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.SCIMSearchRequest,
) (*models.SCIMListResponse, error) {
	startIndex := req.StartIndex
	count := req.Count

	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 {
		count = 100
	}
	if count > 100 {
		count = 100
	}

	return s.ListUsers(ctx, tenantID, startIndex, count, req.Filter)
}

// SearchGroups executes a POST .search against Groups with the given search
// parameters, reusing the existing filter helpers.
func (s *SCIMService) SearchGroups(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.SCIMSearchRequest,
) (*models.SCIMListResponse, error) {
	startIndex := req.StartIndex
	count := req.Count

	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 {
		count = 100
	}
	if count > 100 {
		count = 100
	}

	return s.ListGroups(ctx, tenantID, startIndex, count, req.Filter)
}

// ==================== ETag helpers ====================

// ETagForResource derives the ETag value from a resource's meta version field.
// If meta is nil or version is empty, an empty string is returned and the
// caller should omit the ETag header.
func ETagForResource(meta *models.SCIMMeta) string {
	if meta == nil || meta.Version == "" {
		return ""
	}
	return `"` + meta.Version + `"`
}

// VersionFromETag strips the surrounding quotes from an ETag value (both
// strong and weak form) to recover the raw version string stored in meta.
func VersionFromETag(etag string) string {
	etag = strings.TrimSpace(etag)
	etag = strings.TrimPrefix(etag, "W/")
	return strings.Trim(etag, `"`)
}

// ==================== Private helpers ====================

// parseBulkPath splits a Bulk operation path such as "/Users/some-uuid" into
// ("Users", "some-uuid", nil).  Paths without an ID component (e.g. "/Users")
// return ("Users", "", nil).
func parseBulkPath(path string) (resourceType, resourceID string, err error) {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", "", fmt.Errorf("bulk path %q is empty", path)
	}
	resourceType = parts[0]
	if len(parts) == 2 {
		resourceID = parts[1]
	}
	return resourceType, resourceID, nil
}

// parseResourceID parses and validates a UUID resource ID string.
func parseResourceID(id string) (uuid.UUID, error) {
	if id == "" {
		return uuid.Nil, fmt.Errorf("resource ID is required for this operation")
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid resource ID %q: %w", id, err)
	}
	return parsed, nil
}

// decodeBulkData round-trips the op.Data interface{} (which arrives as
// map[string]interface{} from JSON decode) into the target type T.
func decodeBulkData[T any](data interface{}) (*T, error) {
	if data == nil {
		return nil, fmt.Errorf("operation data is required")
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal data: %w", err)
	}
	var target T
	if err := json.Unmarshal(raw, &target); err != nil {
		return nil, fmt.Errorf("unmarshal data: %w", err)
	}
	return &target, nil
}

// bulkError builds a failure SCIMBulkOperationResult.
func bulkError(base models.SCIMBulkOperationResult, status int, scimType, detail string) models.SCIMBulkOperationResult {
	base.Status = strconv.Itoa(status)
	base.Response = models.SCIMError{
		Schemas:  []string{models.SCIMSchemaError},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	}
	return base
}
