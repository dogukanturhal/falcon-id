// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"github.com/google/uuid"
)

// RefreshIdpSessionAuthTime updates only a verified user's existing SSO
// record. Atomic XX/KEEPTTL prevents racing logout from resurrecting it.
func (s *SessionCache) RefreshIdpSessionAuthTime(ctx context.Context, idpID, userID, sessionID uuid.UUID, authTime int64) (bool, error) {
	result, err := s.client.Redis().Eval(ctx, `local raw=redis.call('GET',KEYS[1]); if not raw then return 0 end; local data=cjson.decode(raw); if data.user_id~=ARGV[1] or data.session_id~=ARGV[2] then return 0 end; data.auth_time=tonumber(ARGV[3]); redis.call('SET',KEYS[1],cjson.encode(data),'XX','KEEPTTL'); return 1`, []string{s.idpSessionKey(idpID)}, userID.String(), sessionID.String(), authTime).Int64()
	return result == 1, err
}

// EndIdpSession also invalidates any 60-second MFA completion replay for
// this SQL session. Deleting the SSO cookie alone must not let a cached MFA
// response resurrect it after the user deliberately signs out.
func (s *SessionCache) EndIdpSession(ctx context.Context, idpID uuid.UUID) error {
	return s.client.Redis().Eval(ctx, `local raw=redis.call('GET',KEYS[1]); if raw then local data=cjson.decode(raw); if data.session_id and data.session_id~='00000000-0000-0000-0000-000000000000' then redis.call('SET','mfa:completion-revoked:'..data.session_id,'1','EX',60) end end; return redis.call('DEL',KEYS[1])`, []string{s.idpSessionKey(idpID)}).Err()
}
