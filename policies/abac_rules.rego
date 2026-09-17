package falcon.authz.abac

# OPA 1.0+ requires the `if` keyword before every rule body. Without
# it the compiler returns `rego_parse_error: 'if' keyword is required
# before rule body` at startup. See policies/authz.rego for the
# upstream reference.

# PATTERN 1: RESOURCE OWNERSHIP
# User can read their own records
allow if {
    input.action == "read"
    input.resource.owner_id == input.user.id
}

# User can update their own records
allow if {
    input.action == "update"
    input.resource.owner_id == input.user.id
}

# User can delete their own records
allow if {
    input.action == "delete"
    input.resource.owner_id == input.user.id
}

# PATTERN 2: DEPARTMENT SCOPING
# Manager can access all records in their department
allow if {
    input.user.roles[_] == "manager"
    input.resource.attributes.department == input.user.department
}

# Director can access records in all sub-departments
allow if {
    input.user.roles[_] == "director"
    startswith(input.resource.attributes.department, input.user.department)
}

# PATTERN 3: AMOUNT/APPROVAL LIMITS
# Staff can approve up to $1,000
allow if {
    input.action == "approve"
    input.resource.type == "purchase_order"
    input.user.roles[_] == "user"
    input.resource.attributes.amount <= 1000
}

# Manager can approve up to $10,000
allow if {
    input.action == "approve"
    input.resource.type == "purchase_order"
    input.user.roles[_] == "manager"
    input.resource.attributes.amount <= 10000
}

# Director can approve up to $50,000
allow if {
    input.action == "approve"
    input.resource.type == "purchase_order"
    input.user.roles[_] == "director"
    input.resource.attributes.amount <= 50000
}

# Admin can approve any amount
allow if {
    input.action == "approve"
    input.resource.type == "purchase_order"
    input.user.roles[_] == "admin"
}

# TENANT ISOLATION - deny if different tenant
deny if {
    input.resource.tenant_id != input.user.tenant_id
}
