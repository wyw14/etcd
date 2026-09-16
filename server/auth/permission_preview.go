// Copyright 2026 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"go.etcd.io/etcd/api/v3/authpb"
)

// PermissionPreviewChangeType is the kind of an authorization configuration
// change proposed to a permission preview.
type PermissionPreviewChangeType int

const (
	// PermissionPreviewRoleGrantPermission grants a permission to a role, or
	// updates the permission type of an existing grant. It follows the same
	// validation and semantics as AuthStore.RoleGrantPermission.
	PermissionPreviewRoleGrantPermission PermissionPreviewChangeType = iota
	// PermissionPreviewRoleRevokePermission revokes an exactly matching
	// permission (key and range end) from a role. It follows the same
	// validation and semantics as AuthStore.RoleRevokePermission.
	PermissionPreviewRoleRevokePermission
	// PermissionPreviewUserGrantRole grants a role to a user. It follows the
	// same validation and semantics as AuthStore.UserGrantRole.
	PermissionPreviewUserGrantRole
	// PermissionPreviewUserRevokeRole revokes a role from a user. It follows
	// the same validation and semantics as AuthStore.UserRevokeRole.
	PermissionPreviewUserRevokeRole
)

// PermissionPreviewChange is a single proposed, not yet applied, authorization
// configuration change. Changes are validated and simulated in order.
type PermissionPreviewChange struct {
	// Type is the kind of the change.
	Type PermissionPreviewChangeType

	// User is the target user of user-role membership changes.
	User string
	// Role is the target role of role-permission changes, or the role granted
	// or revoked in a user-role membership change.
	Role string

	// Perm is the permission granted or revoked by a role-permission change.
	Perm *authpb.Permission
}

// PermissionPreviewRange is a normalized key interval of a preview result.
// RangeEnd follows the usual etcd conventions:
//   - nil (zero length) means the range covers the single Key;
//   - a single zero byte ([]byte{0}) means the range is open ended;
//   - otherwise the range is [Key, RangeEnd).
type PermissionPreviewRange struct {
	Key      []byte
	RangeEnd []byte
}

// PermissionPreviewUserChange describes how the effective read and write
// intervals of one user would change if the proposed changes were applied.
// All interval slices are normalized (merged) and stably sorted by begin key.
type PermissionPreviewUserChange struct {
	User string

	// ReadBefore and ReadAfter are the effective read intervals before and
	// after the proposed changes.
	ReadBefore []PermissionPreviewRange
	ReadAfter  []PermissionPreviewRange
	// ReadAdded contains the intervals newly readable by the user.
	ReadAdded []PermissionPreviewRange
	// ReadRevoked contains the intervals no longer readable by the user.
	ReadRevoked []PermissionPreviewRange

	// WriteBefore and WriteAfter are the effective write intervals before and
	// after the proposed changes.
	WriteBefore []PermissionPreviewRange
	WriteAfter  []PermissionPreviewRange
	// WriteAdded contains the intervals newly writable by the user.
	WriteAdded []PermissionPreviewRange
	// WriteRevoked contains the intervals no longer writable by the user.
	WriteRevoked []PermissionPreviewRange
}

// PermissionPreviewResult is the result of a successful permission preview.
// A preview never mutates users, roles, the permission cache or the auth
// revision.
type PermissionPreviewResult struct {
	// AuthRevision is the authorization configuration revision the preview
	// was computed at. A concurrent configuration update invalidates the
	// observation point and makes the preview fail with ErrAuthOldRevision.
	AuthRevision uint64

	// Users contains only the users whose effective read or write intervals
	// would actually change, stably sorted by user name.
	Users []PermissionPreviewUserChange
}

var (
	// ErrPermissionPreviewTooManyChanges is returned when a preview request
	// contains more proposed changes than the configured limit.
	ErrPermissionPreviewTooManyChanges = errors.New("auth: too many changes in permission preview request")
	// ErrPermissionPreviewTooManyAffectedUsers is returned when the preview
	// result would contain more affected users than the configured limit.
	ErrPermissionPreviewTooManyAffectedUsers = errors.New("auth: too many affected users in permission preview result")
	// ErrPermissionPreviewResultTooLarge is returned when the preview result
	// would contain more ranges than the configured limit.
	ErrPermissionPreviewResultTooLarge = errors.New("auth: permission preview result exceeds the range limit")
)

// Permission preview limits. They bound the work and the size of a preview
// result; hitting any of them terminates the preview without a result.
var (
	permissionPreviewMaxChanges       = 128
	permissionPreviewMaxAffectedUsers = 512
	permissionPreviewMaxRanges        = 8192
)

// PermissionPreviewInvalidChangeError identifies a proposed change that cannot
// be applied to the authorization configuration observed by the preview. The
// preview is atomic: when this error is returned no partial result is produced.
type PermissionPreviewInvalidChangeError struct {
	// Index is the zero-based position of the invalid change in the request.
	Index int
	// Change is the rejected change.
	Change *PermissionPreviewChange
	// Err is the underlying validation error, e.g. ErrRoleNotFound,
	// ErrUserNotFound, ErrRoleNotGranted, ErrPermissionNotGranted,
	// ErrPermissionNotGiven or ErrInvalidAuthMgmt.
	Err error
}

func (e *PermissionPreviewInvalidChangeError) Error() string {
	return fmt.Sprintf("auth: invalid permission preview change at index %d (%s): %v", e.Index, changeDescription(e.Change), e.Err)
}

func (e *PermissionPreviewInvalidChangeError) Unwrap() error { return e.Err }

func changeDescription(ch *PermissionPreviewChange) string {
	if ch == nil {
		return "nil change"
	}
	switch ch.Type {
	case PermissionPreviewRoleGrantPermission:
		return fmt.Sprintf("grant permission to role %q", ch.Role)
	case PermissionPreviewRoleRevokePermission:
		return fmt.Sprintf("revoke permission from role %q", ch.Role)
	case PermissionPreviewUserGrantRole:
		return fmt.Sprintf("grant role %q to user %q", ch.Role, ch.User)
	case PermissionPreviewUserRevokeRole:
		return fmt.Sprintf("revoke role %q from user %q", ch.Role, ch.User)
	default:
		return "unknown change type"
	}
}

// keyRange is a half-open interval [begin, end) over the byte-affine key
// space used by adt.BytesAffineComparable. A nil end denotes the open,
// unbounded upper end (which maps to a []byte{0} range end in etcd requests).
type keyRange struct {
	begin []byte
	end   []byte
}

// authConfigSnapshot is a point-in-time, mutable copy of the authorization
// configuration. Mutating the snapshot never touches the auth backend.
type authConfigSnapshot struct {
	revision uint64
	enabled  bool
	users    map[string]*authpb.User
	roles    map[string]*authpb.Role
}

func snapshotAuthConfig(tx UnsafeAuthReader) *authConfigSnapshot {
	snap := &authConfigSnapshot{
		revision: tx.UnsafeReadAuthRevision(),
		enabled:  tx.UnsafeReadAuthEnabled(),
		users:    make(map[string]*authpb.User),
		roles:    make(map[string]*authpb.Role),
	}
	for _, u := range tx.UnsafeGetAllUsers() {
		snap.users[string(u.Name)] = cloneUserForPreview(u)
	}
	for _, r := range tx.UnsafeGetAllRoles() {
		snap.roles[string(r.Name)] = cloneRoleForPreview(r)
	}
	return snap
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func cloneUserForPreview(u *authpb.User) *authpb.User {
	cu := &authpb.User{
		Name:    cloneBytes(u.Name),
		Options: u.Options,
	}
	if len(u.Roles) > 0 {
		cu.Roles = append(make([]string, 0, len(u.Roles)), u.Roles...)
	}
	return cu
}

func cloneRoleForPreview(r *authpb.Role) *authpb.Role {
	cr := &authpb.Role{Name: cloneBytes(r.Name)}
	for _, p := range r.KeyPermission {
		cr.KeyPermission = append(cr.KeyPermission, &authpb.Permission{
			PermType: p.PermType,
			Key:      cloneBytes(p.Key),
			RangeEnd: cloneBytes(p.RangeEnd),
		})
	}
	return cr
}

// apply simulates one proposed change on the snapshot. Its validation rules
// mirror the mutating AuthStore methods so that a preview fails exactly when
// the real change would fail.
func (s *authConfigSnapshot) apply(ch *PermissionPreviewChange) error {
	switch ch.Type {
	case PermissionPreviewRoleGrantPermission:
		return s.applyRoleGrantPermission(ch)
	case PermissionPreviewRoleRevokePermission:
		return s.applyRoleRevokePermission(ch)
	case PermissionPreviewUserGrantRole:
		return s.applyUserGrantRole(ch)
	case PermissionPreviewUserRevokeRole:
		return s.applyUserRevokeRole(ch)
	default:
		return ErrInvalidAuthMgmt
	}
}

func (s *authConfigSnapshot) applyRoleGrantPermission(ch *PermissionPreviewChange) error {
	if ch.Perm == nil {
		return ErrPermissionNotGiven
	}
	if !isValidPermissionRange(ch.Perm.Key, ch.Perm.RangeEnd) {
		return ErrInvalidAuthMgmt
	}

	role := s.roles[ch.Role]
	if role == nil {
		return ErrRoleNotFound
	}

	idx := sort.Search(len(role.KeyPermission), func(i int) bool {
		return bytes.Compare(role.KeyPermission[i].Key, ch.Perm.Key) >= 0
	})

	if idx < len(role.KeyPermission) &&
		bytes.Equal(role.KeyPermission[idx].Key, ch.Perm.Key) &&
		bytes.Equal(role.KeyPermission[idx].RangeEnd, ch.Perm.RangeEnd) {
		// update existing permission
		role.KeyPermission[idx].PermType = ch.Perm.PermType
		return nil
	}

	// append new permission to the role
	newPerm := &authpb.Permission{
		Key:      cloneBytes(ch.Perm.Key),
		RangeEnd: cloneBytes(ch.Perm.RangeEnd),
		PermType: ch.Perm.PermType,
	}
	role.KeyPermission = append(role.KeyPermission, newPerm)
	sort.Sort(permSlice(role.KeyPermission))
	return nil
}

func (s *authConfigSnapshot) applyRoleRevokePermission(ch *PermissionPreviewChange) error {
	role := s.roles[ch.Role]
	if role == nil {
		return ErrRoleNotFound
	}

	var key, rangeEnd []byte
	if ch.Perm != nil {
		key, rangeEnd = ch.Perm.Key, ch.Perm.RangeEnd
	}

	updatedRole := &authpb.Role{Name: role.Name}
	for _, perm := range role.KeyPermission {
		if !bytes.Equal(perm.Key, key) || !bytes.Equal(perm.RangeEnd, rangeEnd) {
			updatedRole.KeyPermission = append(updatedRole.KeyPermission, perm)
		}
	}

	if len(role.KeyPermission) == len(updatedRole.KeyPermission) {
		return ErrPermissionNotGranted
	}

	s.roles[ch.Role] = updatedRole
	return nil
}

func (s *authConfigSnapshot) applyUserGrantRole(ch *PermissionPreviewChange) error {
	user := s.users[ch.User]
	if user == nil {
		return ErrUserNotFound
	}

	if ch.Role != rootRole {
		if _, ok := s.roles[ch.Role]; !ok {
			return ErrRoleNotFound
		}
	}

	idx := sort.SearchStrings(user.Roles, ch.Role)
	if idx < len(user.Roles) && user.Roles[idx] == ch.Role {
		// granting an already granted role is a no-op, same as the store
		return nil
	}

	user.Roles = append(user.Roles, ch.Role)
	sort.Strings(user.Roles)
	return nil
}

func (s *authConfigSnapshot) applyUserRevokeRole(ch *PermissionPreviewChange) error {
	if s.enabled && ch.User == rootUser && ch.Role == rootRole {
		return ErrInvalidAuthMgmt
	}

	user := s.users[ch.User]
	if user == nil {
		return ErrUserNotFound
	}

	updatedRoles := make([]string, 0, len(user.Roles))
	for _, role := range user.Roles {
		if role != ch.Role {
			updatedRoles = append(updatedRoles, role)
		}
	}

	if len(updatedRoles) == len(user.Roles) {
		return ErrRoleNotGranted
	}

	user.Roles = updatedRoles
	return nil
}

// permissionToKeyRange converts a stored permission to a key interval using
// exactly the same rules as getMergedPerms:
//   - an open-ended range end ([]byte{0}) becomes the unbounded end;
//   - an empty range end becomes the single-key point [key, key\x00);
//   - any other range end is the half-open interval [key, rangeEnd).
func permissionToKeyRange(p *authpb.Permission) keyRange {
	if len(p.RangeEnd) == 0 {
		end := make([]byte, len(p.Key)+1)
		copy(end, p.Key)
		return keyRange{begin: cloneBytes(p.Key), end: end}
	}
	if isOpenEnded(p.RangeEnd) {
		return keyRange{begin: cloneBytes(p.Key)}
	}
	return keyRange{begin: cloneBytes(p.Key), end: cloneBytes(p.RangeEnd)}
}

// cmpKeyBoundary compares two interval boundaries in the byte-affine order:
// empty (nil) boundaries are larger than every real key, matching
// BytesAffineComparable.
func cmpKeyBoundary(a, b []byte) int {
	if len(a) == 0 {
		if len(b) == 0 {
			return 0
		}
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	return bytes.Compare(a, b)
}

// mergeKeyRanges returns the input intervals sorted and union-merged:
// overlapping or adjacent (sharing an endpoint) intervals become one.
func mergeKeyRanges(in []keyRange) []keyRange {
	if len(in) == 0 {
		return nil
	}
	sorted := make([]keyRange, len(in))
	copy(sorted, in)
	sort.Slice(sorted, func(i, j int) bool {
		if c := cmpKeyBoundary(sorted[i].begin, sorted[j].begin); c != 0 {
			return c < 0
		}
		return cmpKeyBoundary(sorted[i].end, sorted[j].end) < 0
	})

	out := make([]keyRange, 0, len(sorted))
	for _, r := range sorted {
		n := len(out)
		if n == 0 || cmpKeyBoundary(r.begin, out[n-1].end) > 0 {
			out = append(out, keyRange{begin: cloneBytes(r.begin), end: cloneBytes(r.end)})
			continue
		}
		if cmpKeyBoundary(r.end, out[n-1].end) > 0 {
			out[n-1].end = cloneBytes(r.end)
		}
	}
	return out
}

// subtractKeyRanges returns the parts of the normalized intervals in a that are
// not covered by the normalized intervals in b. Both inputs must be sorted and
// disjoint (as produced by mergeKeyRanges). The result is normalized.
func subtractKeyRanges(a, b []keyRange) []keyRange {
	var out []keyRange
	for _, x := range a {
		pieces := []keyRange{{begin: cloneBytes(x.begin), end: cloneBytes(x.end)}}
		for _, y := range b {
			if cmpKeyBoundary(y.end, x.begin) <= 0 {
				continue
			}
			if cmpKeyBoundary(y.begin, x.end) >= 0 {
				break
			}
			var next []keyRange
			for _, p := range pieces {
				// no overlap: y ends before p, or y starts at/after p
				if cmpKeyBoundary(y.end, p.begin) <= 0 || cmpKeyBoundary(y.begin, p.end) >= 0 {
					next = append(next, p)
					continue
				}
				// left remainder [p.begin, y.begin)
				if cmpKeyBoundary(p.begin, y.begin) < 0 {
					next = append(next, keyRange{begin: p.begin, end: cloneBytes(y.begin)})
				}
				// right remainder [y.end, p.end)
				if cmpKeyBoundary(y.end, p.end) < 0 {
					next = append(next, keyRange{begin: cloneBytes(y.end), end: p.end})
				}
			}
			pieces = next
		}
		out = append(out, pieces...)
	}
	return out
}

// toPreviewRange canonicalizes a normalized interval back to etcd request
// conventions.
func toPreviewRange(r keyRange) PermissionPreviewRange {
	out := PermissionPreviewRange{Key: cloneBytes(r.begin)}
	if len(r.end) == 0 {
		// open-ended range
		out.RangeEnd = []byte{0}
		return out
	}
	// single-key point: end is exactly begin with one trailing zero byte
	if len(r.end) == len(r.begin)+1 && bytes.Equal(r.end[:len(r.begin)], r.begin) && r.end[len(r.begin)] == 0 {
		return out
	}
	out.RangeEnd = cloneBytes(r.end)
	return out
}

func toPreviewRanges(in []keyRange) []PermissionPreviewRange {
	if len(in) == 0 {
		return nil
	}
	out := make([]PermissionPreviewRange, 0, len(in))
	for _, r := range in {
		out = append(out, toPreviewRange(r))
	}
	return out
}

type roleRanges struct {
	read  []keyRange
	write []keyRange
}

func buildRoleRanges(roles map[string]*authpb.Role) map[string]roleRanges {
	cache := make(map[string]roleRanges, len(roles))
	for name, role := range roles {
		var reads, writes []keyRange
		for _, p := range role.KeyPermission {
			kr := permissionToKeyRange(p)
			switch p.PermType {
			case authpb.Permission_READWRITE:
				reads = append(reads, kr)
				writes = append(writes, kr)
			case authpb.Permission_READ:
				reads = append(reads, kr)
			case authpb.Permission_WRITE:
				writes = append(writes, kr)
			}
		}
		cache[name] = roleRanges{read: mergeKeyRanges(reads), write: mergeKeyRanges(writes)}
	}
	return cache
}

// fullKeySpace is the interval covering every possible key, granted by the
// root role (see isOpPermitted's hasRootRole short-circuit).
var fullKeySpace = []keyRange{{begin: []byte{0}, end: nil}}

func userEffectiveRanges(u *authpb.User, roles map[string]roleRanges) (read, write []keyRange) {
	if hasRootRole(u) {
		return cloneKeyRanges(fullKeySpace), cloneKeyRanges(fullKeySpace)
	}
	var reads, writes []keyRange
	for _, roleName := range u.Roles {
		if rr, ok := roles[roleName]; ok {
			reads = append(reads, rr.read...)
			writes = append(writes, rr.write...)
		}
	}
	return mergeKeyRanges(reads), mergeKeyRanges(writes)
}

func cloneKeyRanges(in []keyRange) []keyRange {
	if len(in) == 0 {
		return nil
	}
	out := make([]keyRange, len(in))
	for i := range in {
		out[i] = keyRange{begin: cloneBytes(in[i].begin), end: cloneBytes(in[i].end)}
	}
	return out
}

// PreviewPermissionChanges computes a read-only preview of how a sequence of
// proposed role-permission and user-role changes would affect the effective
// read and write key intervals of each affected user.
//
// The preview is computed at a single authorization configuration
// observation point and fails with ErrAuthOldRevision when a concurrent
// permission update invalidates that point. It never writes users, roles or
// the range permission cache, never bumps the auth revision and never
// invalidates existing tokens.
//
// Validation is atomic: if any proposed change is invalid, the change is
// reported through PermissionPreviewInvalidChangeError and no partial result
// is returned. The method requires administrator (root role) privileges and
// returns ErrPermissionDenied otherwise.
func (as *authStore) PreviewPermissionChanges(ctx context.Context, authInfo *AuthInfo, changes []*PermissionPreviewChange) (*PermissionPreviewResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// administrator only; a nil authInfo is accepted only while auth is disabled
	if err := as.IsAdminPermitted(authInfo); err != nil {
		return nil, err
	}

	if len(changes) > permissionPreviewMaxChanges {
		return nil, fmt.Errorf("%w: %d changes (limit %d)", ErrPermissionPreviewTooManyChanges, len(changes), permissionPreviewMaxChanges)
	}
	for i, ch := range changes {
		if ch == nil {
			return nil, &PermissionPreviewInvalidChangeError{Index: i, Err: ErrInvalidAuthMgmt}
		}
	}

	// Capture a single, consistent observation point. Only a read transaction
	// is used: the preview performs no backend writes.
	tx := as.be.ReadTx()
	tx.RLock()
	before := snapshotAuthConfig(tx)
	after := snapshotAuthConfig(tx)
	tx.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	touchedRoles := make(map[string]struct{})
	explicitUsers := make(map[string]struct{})

	for i, ch := range changes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := after.apply(ch); err != nil {
			return nil, &PermissionPreviewInvalidChangeError{Index: i, Change: ch, Err: err}
		}
		switch ch.Type {
		case PermissionPreviewRoleGrantPermission, PermissionPreviewRoleRevokePermission:
			touchedRoles[ch.Role] = struct{}{}
		case PermissionPreviewUserGrantRole, PermissionPreviewUserRevokeRole:
			explicitUsers[ch.User] = struct{}{}
		}
	}

	// The observation point may have been invalidated while simulating.
	if as.Revision() != after.revision {
		return nil, ErrAuthOldRevision
	}

	candidates := make(map[string]struct{})
	for name := range explicitUsers {
		if _, ok := after.users[name]; ok {
			candidates[name] = struct{}{}
		}
	}
	for name, u := range after.users {
		for _, roleName := range u.Roles {
			if _, ok := touchedRoles[roleName]; ok {
				candidates[name] = struct{}{}
				break
			}
		}
	}

	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)

	beforeRoles := buildRoleRanges(before.roles)
	afterRoles := buildRoleRanges(after.roles)

	result := &PermissionPreviewResult{AuthRevision: before.revision}
	for _, name := range names {
		beforeUser := before.users[name]
		afterUser := after.users[name]
		if beforeUser == nil || afterUser == nil {
			// the supported changes never create or delete users
			continue
		}

		readBefore, writeBefore := userEffectiveRanges(beforeUser, beforeRoles)
		readAfter, writeAfter := userEffectiveRanges(afterUser, afterRoles)

		readAdded := subtractKeyRanges(readAfter, readBefore)
		readRevoked := subtractKeyRanges(readBefore, readAfter)
		writeAdded := subtractKeyRanges(writeAfter, writeBefore)
		writeRevoked := subtractKeyRanges(writeBefore, writeAfter)

		if len(readAdded) == 0 && len(readRevoked) == 0 && len(writeAdded) == 0 && len(writeRevoked) == 0 {
			// grants absorbed by overlapping roles or no-op changes
			continue
		}

		result.Users = append(result.Users, PermissionPreviewUserChange{
			User:         name,
			ReadBefore:   toPreviewRanges(readBefore),
			ReadAfter:    toPreviewRanges(readAfter),
			ReadAdded:    toPreviewRanges(readAdded),
			ReadRevoked:  toPreviewRanges(readRevoked),
			WriteBefore:  toPreviewRanges(writeBefore),
			WriteAfter:   toPreviewRanges(writeAfter),
			WriteAdded:   toPreviewRanges(writeAdded),
			WriteRevoked: toPreviewRanges(writeRevoked),
		})
	}

	if len(result.Users) > permissionPreviewMaxAffectedUsers {
		return nil, fmt.Errorf("%w: %d users (limit %d)", ErrPermissionPreviewTooManyAffectedUsers, len(result.Users), permissionPreviewMaxAffectedUsers)
	}

	totalRanges := 0
	for i := range result.Users {
		u := &result.Users[i]
		totalRanges += len(u.ReadBefore) + len(u.ReadAfter) + len(u.ReadAdded) + len(u.ReadRevoked) +
			len(u.WriteBefore) + len(u.WriteAfter) + len(u.WriteAdded) + len(u.WriteRevoked)
	}
	if totalRanges > permissionPreviewMaxRanges {
		return nil, fmt.Errorf("%w: %d ranges (limit %d)", ErrPermissionPreviewResultTooLarge, totalRanges, permissionPreviewMaxRanges)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Re-check the observation point after the result was built.
	if as.Revision() != before.revision {
		return nil, ErrAuthOldRevision
	}

	return result, nil
}
