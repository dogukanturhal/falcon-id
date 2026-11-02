package falcon.pdp.v1_test

import data.falcon.pdp.v1

test_empty_policy_allows_with_no_denies if {
	d := v1.decision with input as {"subject": {"id": "u1"}, "action": {"permission": "x:y:z"}}
	d.allow
	count(d.denies) == 0
	count(d.obligations) == 0
}

test_empty_policy_ignores_admin_role if {
	d := v1.decision with input as {"subject": {"roles": [{"key": "admin"}]}}
	d.allow
	count(d.denies) == 0
}

test_deny_rule_flips_allow if {
	d := v1.decision with data.falcon.pdp.v1.deny as {{"rule": "r1", "code": "c1", "params": {}}}
	not d.allow
	count(d.denies) == 1
}
