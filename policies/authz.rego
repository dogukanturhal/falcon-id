package falcon.authz

# OPA 1.0+ requires the `if` keyword before rule bodies and `:=` for
# `default` value assignment. The runtime in opa_service.go imports
# `github.com/open-policy-agent/opa/v1/...`, which compiles in v1 mode
# and rejects the legacy v0 sugar with `rego_parse_error: 'if' keyword
# is required before rule body`.
# See https://www.openpolicyagent.org/docs/v0-upgrade/

default allow := false

# Super admin - has all permissions via wildcard
allow if {
    input.user.permissions[_] == "*"
}

# Admin role has full access
allow if {
    input.user.roles[_] == "admin"
}

# Exact permission match
allow if {
    input.user.permissions[_] == input.action
}

# Wildcard permission match (e.g., "core:users:*" matches "core:users:read")
allow if {
    perm := input.user.permissions[_]
    wildcard_match(perm, input.action)
}

# Helper: Wildcard matching for suffix wildcards (most common case)
wildcard_match(pattern, permission) if {
    endswith(pattern, ":*")
    prefix := trim_suffix(pattern, "*")
    startswith(permission, prefix)
}
