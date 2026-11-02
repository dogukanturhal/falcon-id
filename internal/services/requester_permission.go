// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// requesterPermissionRelation maps narrow intake and its company-selector reference
// grant in addition to access_grant. Never map these permissions to viewer/editor.
func requesterPermissionRelation(name string) string {
	switch name {
	case "cmms:maintenance_requests:create_own":
		return "maintenance_request_creator"
	case "cmms:maintenance_requests:read_own":
		return "maintenance_request_reader"
	case "core:legal_entities:read":
		return "legal_entity_reader"
	default:
		return ""
	}
}
