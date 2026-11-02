package falcon.pdp.v1

# Deny-only policy set. Rules contribute objects of the form
#   {"rule": "<id>", "code": "<machine code>", "params": {...}}
# to `deny`. A decision never grants access on its own: the caller combines
# it as `rebac_allow AND count(denies) == 0`.
#
# No rules are defined yet, so every request is allowed with no denies.
# Rule files added later must replace this default with a partial set
# (`deny contains d if {...}`) in the same commit.
default deny := set()

default obligations := []

decision := {
	"allow": count(deny) == 0,
	"denies": sort(deny),
	"obligations": obligations,
}
