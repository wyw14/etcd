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

// Independent acceptance verification for precheck 529.
//
// The preview is checked against the real authorization path: the same changes
// are applied through the ordinary AuthStore methods and every interval the
// preview reported as added or revoked is then probed with IsRangePermitted.
// Nothing here reuses the submission's own helpers.

package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/metadata"

	"go.etcd.io/etcd/api/v3/authpb"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

type zzv529Fixture struct {
	as         AuthStore
	root       *AuthInfo
	adminInfo  *AuthInfo
	adminToken string
}

// zzv529NewStore builds an enabled auth store with a root user and an
// authenticated administrator that also owns a real token.
func zzv529NewStore(t *testing.T) *zzv529Fixture {
	t.Helper()
	tp, err := NewTokenProvider(zaptest.NewLogger(t), tokenTypeSimple, dummyIndexWaiter, simpleTokenTTLDefault)
	require.NoError(t, err)
	as := NewAuthStore(zaptest.NewLogger(t), newBackendMock(), tp, bcrypt.MinCost)
	t.Cleanup(func() { require.NoError(t, as.Close()) })
	require.NoError(t, enableAuthAndCreateRoot(as))

	_, err = as.UserAdd(&pb.AuthUserAddRequest{
		Name: "admin", HashedPassword: encodePassword("admin-pass"),
		Options: &authpb.UserAddOptions{NoPassword: false},
	})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "admin", Role: "root"})
	require.NoError(t, err)
	authCtx := context.WithValue(
		context.WithValue(t.Context(), AuthenticateParamIndex{}, uint64(1)),
		AuthenticateParamSimpleTokenPrefix{}, "zzv529")
	token, err := as.Authenticate(authCtx, "admin", "admin-pass")
	require.NoError(t, err)

	return &zzv529Fixture{
		as:         as,
		root:       &AuthInfo{Username: "root", Revision: as.Revision()},
		adminInfo:  &AuthInfo{Username: "admin", Revision: as.Revision()},
		adminToken: token.Token,
	}
}

func zzv529AddRole(t *testing.T, as AuthStore, name string) {
	t.Helper()
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: name})
	require.NoError(t, err)
}

func zzv529AddUser(t *testing.T, as AuthStore, name string) {
	t.Helper()
	_, err := as.UserAdd(&pb.AuthUserAddRequest{Name: name, Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
}

func zzv529BindRole(t *testing.T, as AuthStore, user, role string) {
	t.Helper()
	_, err := as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: user, Role: role})
	require.NoError(t, err)
}

func zzv529ApplyPerm(t *testing.T, as AuthStore, role string, typ authpb.Permission_Type, key, rangeEnd []byte) {
	t.Helper()
	_, err := as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: role, Perm: &authpb.Permission{PermType: typ, Key: key, RangeEnd: rangeEnd},
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// change builders
// ---------------------------------------------------------------------------

func zzv529GrantPermChange(role string, typ authpb.Permission_Type, key, rangeEnd []byte) *PermissionPreviewChange {
	return &PermissionPreviewChange{
		Type: PermissionPreviewRoleGrantPermission,
		Role: role,
		Perm: &authpb.Permission{PermType: typ, Key: key, RangeEnd: rangeEnd},
	}
}

func zzv529RevokePermChange(role string, key, rangeEnd []byte) *PermissionPreviewChange {
	return &PermissionPreviewChange{
		Type: PermissionPreviewRoleRevokePermission,
		Role: role,
		Perm: &authpb.Permission{Key: key, RangeEnd: rangeEnd},
	}
}

func zzv529GrantRoleChange(user, role string) *PermissionPreviewChange {
	return &PermissionPreviewChange{Type: PermissionPreviewUserGrantRole, User: user, Role: role}
}

func zzv529RevokeRoleChange(user, role string) *PermissionPreviewChange {
	return &PermissionPreviewChange{Type: PermissionPreviewUserRevokeRole, User: user, Role: role}
}

// zzv529ApplyToStore performs the same changes through the real mutating API.
func zzv529ApplyToStore(t *testing.T, as AuthStore, changes []*PermissionPreviewChange) {
	t.Helper()
	for i, ch := range changes {
		switch ch.Type {
		case PermissionPreviewRoleGrantPermission:
			_, err := as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{Name: ch.Role, Perm: ch.Perm})
			require.NoErrorf(t, err, "apply change %d", i)
		case PermissionPreviewRoleRevokePermission:
			_, err := as.RoleRevokePermission(&pb.AuthRoleRevokePermissionRequest{
				Role: ch.Role, Key: ch.Perm.Key, RangeEnd: ch.Perm.RangeEnd,
			})
			require.NoErrorf(t, err, "apply change %d", i)
		case PermissionPreviewUserGrantRole:
			_, err := as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: ch.User, Role: ch.Role})
			require.NoErrorf(t, err, "apply change %d", i)
		case PermissionPreviewUserRevokeRole:
			_, err := as.UserRevokeRole(&pb.AuthUserRevokeRoleRequest{Name: ch.User, Role: ch.Role})
			require.NoErrorf(t, err, "apply change %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// probes against the real authorization path
// ---------------------------------------------------------------------------

// zzv529ProbeInterval asks the real authorization path whether user may access
// the interval. An open-ended range end is written as []byte{0}.
func zzv529ProbeInterval(t *testing.T, as AuthStore, user string, r PermissionPreviewRange) bool {
	t.Helper()
	info := &AuthInfo{Username: user, Revision: as.Revision()}
	rangeEnd := r.RangeEnd
	if len(rangeEnd) == 1 && rangeEnd[0] == 0 {
		rangeEnd = []byte{0}
	}
	return as.IsRangePermitted(info, r.Key, rangeEnd) == nil
}

// zzv529ProbeRanges asserts that every interval in ranges has the given
// accessibility through the real authorization path.
func zzv529ProbeRanges(t *testing.T, as AuthStore, user string, ranges []PermissionPreviewRange, want bool, label string) {
	t.Helper()
	for i, r := range ranges {
		got := zzv529ProbeInterval(t, as, user, r)
		assert.Equalf(t, want, got, "%s: interval %d key=%q rangeEnd=%q", label, i, r.Key, r.RangeEnd)
	}
}

// zzv529KeysOutside returns the sample keys that the given normalized intervals
// do not cover.
func zzv529KeysOutside(ranges []PermissionPreviewRange, keys [][]byte) [][]byte {
	var outside [][]byte
	for _, key := range keys {
		if !zzv529Covered(ranges, key) {
			outside = append(outside, key)
		}
	}
	return outside
}

// zzv529Covered reports whether the normalized intervals of a preview contain
// the single-key interval for key.
func zzv529Covered(ranges []PermissionPreviewRange, key []byte) bool {
	point := append(append([]byte(nil), key...), 0)
	end := key[len(key)-1] + 1
	succ := append(append([]byte(nil), key[:len(key)-1]...), end)
	for _, r := range ranges {
		begin := r.Key
		var rEnd []byte
		if len(r.RangeEnd) == 1 && r.RangeEnd[0] == 0 {
			rEnd = nil // open ended
		} else if len(r.RangeEnd) == 0 {
			rEnd = point // single key
		} else {
			rEnd = r.RangeEnd
		}
		if bytesCompare(begin, key) > 0 {
			continue
		}
		if rEnd == nil {
			return true
		}
		if bytesCompare(rEnd, succ) >= 0 {
			return true
		}
	}
	return false
}

func bytesCompare(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func zzv529UserChange(t *testing.T, result *PermissionPreviewResult, user string) *PermissionPreviewUserChange {
	t.Helper()
	for i := range result.Users {
		if result.Users[i].User == user {
			return &result.Users[i]
		}
	}
	require.Failf(t, "user missing from the preview result", "user %q, result %+v", user, result.Users)
	return nil
}

func zzv529DescribeRanges(ranges []PermissionPreviewRange) string {
	out := ""
	for i, r := range ranges {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("[%q,%q]", r.Key, r.RangeEnd)
	}
	return out
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// TestZZV529PreviewMatchesRealAuthorization is the core check: the reported
// added and revoked intervals must agree with what the real authorization path
// grants after the same changes are applied.
func TestZZV529PreviewMatchesRealAuthorization(t *testing.T) {
	probeKeys := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e"), []byte("f"), []byte("g")}

	t.Run("grant adds a bounded read interval", func(t *testing.T) {
		fx := zzv529NewStore(t)
		zzv529AddRole(t, fx.as, "r1")
		zzv529AddUser(t, fx.as, "u1")
		zzv529BindRole(t, fx.as, "u1", "r1")
		zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("a"), []byte("c"))

		changes := []*PermissionPreviewChange{
			zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("d"), []byte("f")),
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		change := zzv529UserChange(t, result, "u1")
		t.Logf("added=%s revoked=%s readAfter=%s",
			zzv529DescribeRanges(change.ReadAdded), zzv529DescribeRanges(change.ReadRevoked),
			zzv529DescribeRanges(change.ReadAfter))

		require.Len(t, change.ReadAdded, 1)
		assert.Equal(t, []byte("d"), change.ReadAdded[0].Key)
		assert.Equal(t, []byte("f"), change.ReadAdded[0].RangeEnd)
		assert.Empty(t, change.ReadRevoked)
		assert.Empty(t, change.WriteAdded)
		assert.Empty(t, change.WriteRevoked)

		// The preview must not have changed anything yet.
		zzv529ProbeRanges(t, fx.as, "u1", change.ReadAdded, false, "before applying")
		zzv529ProbeRanges(t, fx.as, "u1", change.ReadBefore, true, "before applying, existing grant")

		zzv529ApplyToStore(t, fx.as, changes)
		zzv529ProbeRanges(t, fx.as, "u1", change.ReadAdded, true, "after applying, added")
		zzv529ProbeRanges(t, fx.as, "u1", change.ReadRevoked, false, "after applying, revoked")
		zzv529ProbeRanges(t, fx.as, "u1", change.ReadAfter, true, "after applying, effective")
		// Keys the report places outside ReadAfter must really be unreadable.
		for _, key := range zzv529KeysOutside(change.ReadAfter, probeKeys) {
			assert.Errorf(t, fx.as.IsRangePermitted(&AuthInfo{Username: "u1", Revision: fx.as.Revision()}, key, nil),
				"key %q is outside the reported effective range and must not be readable", key)
		}
	})

	t.Run("overlapping roles do not report a false revocation", func(t *testing.T) {
		fx := zzv529NewStore(t)
		zzv529AddRole(t, fx.as, "wide")
		zzv529AddRole(t, fx.as, "overlap")
		zzv529AddUser(t, fx.as, "u1")
		zzv529BindRole(t, fx.as, "u1", "wide")
		zzv529BindRole(t, fx.as, "u1", "overlap")
		// wide covers [a,g), overlap covers [c,e).
		zzv529ApplyPerm(t, fx.as, "wide", authpb.Permission_READ, []byte("a"), []byte("g"))
		zzv529ApplyPerm(t, fx.as, "overlap", authpb.Permission_READ, []byte("c"), []byte("e"))

		// Removing the second role must not lose [c,e): the first role still
		// covers it, so the preview must report no revocation at all.
		changes := []*PermissionPreviewChange{zzv529RevokeRoleChange("u1", "overlap")}

		// Cross-check the fixture through the public API before previewing.
		userResp, err := fx.as.UserGet(&pb.AuthUserGetRequest{Name: "u1"})
		require.NoError(t, err)
		wideResp, err := fx.as.RoleGet(&pb.AuthRoleGetRequest{Role: "wide"})
		require.NoError(t, err)
		overlapResp, err := fx.as.RoleGet(&pb.AuthRoleGetRequest{Role: "overlap"})
		require.NoError(t, err)
		t.Logf("fixture: u1 roles=%v; wide perms=%v; overlap perms=%v",
			userResp.Roles, wideResp.Perm, overlapResp.Perm)

		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		t.Logf("revision=%d users=%d", result.AuthRevision, len(result.Users))
		for _, u := range result.Users {
			t.Logf("  user=%s readBefore=%s readAfter=%s readAdded=%s readRevoked=%s writeRevoked=%s",
				u.User, zzv529DescribeRanges(u.ReadBefore), zzv529DescribeRanges(u.ReadAfter),
				zzv529DescribeRanges(u.ReadAdded), zzv529DescribeRanges(u.ReadRevoked),
				zzv529DescribeRanges(u.WriteRevoked))
		}
		// The requirement is that no revocation is reported: either the user is
		// absent from the result entirely, or it is listed with an empty
		// revoked set.
		if len(result.Users) > 0 {
			change := zzv529UserChange(t, result, "u1")
			t.Logf("readBefore=%s readAfter=%s revoked=%s",
				zzv529DescribeRanges(change.ReadBefore), zzv529DescribeRanges(change.ReadAfter),
				zzv529DescribeRanges(change.ReadRevoked))
			assert.Empty(t, change.ReadRevoked, "c..e is still granted by the wide role")
			assert.Empty(t, change.ReadAdded)
			assert.Empty(t, change.WriteRevoked)
		} else {
			t.Logf("no affected user reported, which also means no false revocation")
		}

		zzv529ApplyToStore(t, fx.as, changes)
		for _, key := range [][]byte{[]byte("a"), []byte("b"), []byte("f")} {
			assert.NoErrorf(t, fx.as.IsRangePermitted(&AuthInfo{Username: "u1", Revision: fx.as.Revision()}, key, nil),
				"key %q stays readable through the wide role", key)
		}
		assert.Errorf(t, fx.as.IsRangePermitted(&AuthInfo{Username: "u1", Revision: fx.as.Revision()}, []byte("g"), nil),
			"g is the exclusive end of the wide interval")
	})

	t.Run("revoking one of two overlapping roles keeps the uncovered part", func(t *testing.T) {
		fx := zzv529NewStore(t)
		zzv529AddRole(t, fx.as, "r1")
		zzv529AddUser(t, fx.as, "u1")
		zzv529BindRole(t, fx.as, "u1", "r1")
		// One role, two disjoint intervals: revoking one interval loses it.
		zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("a"), []byte("c"))
		zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("e"), []byte("g"))

		changes := []*PermissionPreviewChange{
			zzv529RevokePermChange("r1", []byte("a"), []byte("c")),
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		change := zzv529UserChange(t, result, "u1")
		t.Logf("revoked=%s readAfter=%s",
			zzv529DescribeRanges(change.ReadRevoked), zzv529DescribeRanges(change.ReadAfter))
		require.Len(t, change.ReadRevoked, 1)
		assert.Equal(t, []byte("a"), change.ReadRevoked[0].Key)
		assert.Equal(t, []byte("c"), change.ReadRevoked[0].RangeEnd)
		require.Len(t, change.ReadAfter, 1)
		assert.Equal(t, []byte("e"), change.ReadAfter[0].Key)

		zzv529ApplyToStore(t, fx.as, changes)
		zzv529ProbeRanges(t, fx.as, "u1", change.ReadRevoked, false, "revoked interval")
		assert.NoError(t, fx.as.IsRangePermitted(&AuthInfo{Username: "u1", Revision: fx.as.Revision()}, []byte("f"), nil),
			"the untouched interval stays readable")
	})

	t.Run("single key, prefix and open ended ranges use real authorization semantics", func(t *testing.T) {
		fx := zzv529NewStore(t)
		zzv529AddRole(t, fx.as, "r1")
		zzv529AddUser(t, fx.as, "u1")
		zzv529BindRole(t, fx.as, "u1", "r1")

		changes := []*PermissionPreviewChange{
			zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("one"), nil),
			zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("pre"), []byte("prf")),
			zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("tail"), []byte{0}),
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		change := zzv529UserChange(t, result, "u1")
		t.Logf("added=%s", zzv529DescribeRanges(change.ReadAdded))
		require.Len(t, change.ReadAdded, 3)

		// Single key keeps the point representation: no range end.
		assert.Equal(t, []byte("one"), change.ReadAdded[0].Key)
		assert.Empty(t, change.ReadAdded[0].RangeEnd)
		// Prefix stays half-open.
		assert.Equal(t, []byte("pre"), change.ReadAdded[1].Key)
		assert.Equal(t, []byte("prf"), change.ReadAdded[1].RangeEnd)
		// Open ended keeps the single zero byte convention.
		assert.Equal(t, []byte("tail"), change.ReadAdded[2].Key)
		assert.Equal(t, []byte{0}, change.ReadAdded[2].RangeEnd)

		zzv529ApplyToStore(t, fx.as, changes)
		info := &AuthInfo{Username: "u1", Revision: fx.as.Revision()}
		require.NoError(t, fx.as.IsRangePermitted(info, []byte("one"), nil), "the exact key is readable")
		require.NoError(t, fx.as.IsRangePermitted(info, []byte("pre"), []byte("prf")), "the prefix range is readable")
		require.NoError(t, fx.as.IsRangePermitted(info, []byte("tail"), []byte{0}), "the open ended range is readable")
		require.NoError(t, fx.as.IsRangePermitted(info, []byte("zzzz"), []byte{0}),
			"an open ended range reaches keys after its start")
		// Keys outside every granted interval stay unreadable: "a" sorts before
		// "one", "prf" is the exclusive end of the prefix and "tail" is the
		// start of the open ended range.
		for _, key := range [][]byte{[]byte("a"), []byte("prf"), []byte("prg")} {
			require.Errorf(t, fx.as.IsRangePermitted(info, key, nil),
				"key %q is outside every granted interval", key)
		}

		// Revoking the exact single-key permission removes exactly that key.
		revoke := []*PermissionPreviewChange{zzv529RevokePermChange("r1", []byte("one"), nil)}
		revokeResult, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, revoke)
		require.NoError(t, err)
		revokeChange := zzv529UserChange(t, revokeResult, "u1")
		require.Len(t, revokeChange.ReadRevoked, 1)
		assert.Equal(t, []byte("one"), revokeChange.ReadRevoked[0].Key)
		assert.Empty(t, revokeChange.ReadRevoked[0].RangeEnd)
		zzv529ApplyToStore(t, fx.as, revoke)
		require.Error(t, fx.as.IsRangePermitted(&AuthInfo{Username: "u1", Revision: fx.as.Revision()}, []byte("one"), nil))
		require.NoError(t, fx.as.IsRangePermitted(&AuthInfo{Username: "u1", Revision: fx.as.Revision()}, []byte("pre"), []byte("prf")),
			"the other intervals stay readable")
	})

	t.Run("write permissions are reported separately from read permissions", func(t *testing.T) {
		fx := zzv529NewStore(t)
		zzv529AddRole(t, fx.as, "r1")
		zzv529AddUser(t, fx.as, "u1")
		zzv529BindRole(t, fx.as, "u1", "r1")
		zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("k"), nil)

		changes := []*PermissionPreviewChange{
			zzv529GrantPermChange("r1", authpb.Permission_WRITE, []byte("w"), []byte("x")),
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		change := zzv529UserChange(t, result, "u1")
		require.Len(t, change.WriteAdded, 1)
		assert.Empty(t, change.ReadAdded, "a write grant does not add read access")
		assert.Equal(t, []byte("w"), change.WriteAdded[0].Key)

		zzv529ApplyToStore(t, fx.as, changes)
		info := &AuthInfo{Username: "u1", Revision: fx.as.Revision()}
		require.NoError(t, fx.as.IsPutPermitted(info, []byte("w")))
		require.Error(t, fx.as.IsPutPermitted(info, []byte("k")), "read permission alone does not allow writes")
		require.NoError(t, fx.as.IsRangePermitted(info, []byte("k"), nil))
		require.Error(t, fx.as.IsRangePermitted(info, []byte("w"), nil),
			"write permission alone does not allow reads")
	})

	t.Run("root role short circuits to the whole keyspace", func(t *testing.T) {
		fx := zzv529NewStore(t)
		zzv529AddRole(t, fx.as, "r1")
		zzv529AddUser(t, fx.as, "u1")
		zzv529BindRole(t, fx.as, "u1", "r1")
		zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("a"), []byte("c"))

		changes := []*PermissionPreviewChange{zzv529GrantRoleChange("u1", "root")}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		change := zzv529UserChange(t, result, "u1")
		t.Logf("root added=%s readAfter=%s", zzv529DescribeRanges(change.ReadAdded),
			zzv529DescribeRanges(change.ReadAfter))
		// The root role covers the whole keyspace; the previously granted
		// interval is already inside it, so the added set is the keyspace minus
		// that interval and must therefore start at the first possible key.
		require.NotEmpty(t, change.ReadAdded)
		assert.Equal(t, []byte{0}, change.ReadAdded[0].Key,
			"the root role covers from the first possible key")
		coversWholeKeyspace := false
		for _, r := range change.ReadAdded {
			if len(r.RangeEnd) == 1 && r.RangeEnd[0] == 0 {
				coversWholeKeyspace = true
			}
		}
		assert.True(t, coversWholeKeyspace,
			"an open ended interval must reach every key after the existing grant")

		zzv529ApplyToStore(t, fx.as, changes)
		info := &AuthInfo{Username: "u1", Revision: fx.as.Revision()}
		for _, key := range [][]byte{[]byte("a"), []byte("m"), []byte("zzzz")} {
			require.NoErrorf(t, fx.as.IsRangePermitted(info, key, nil), "root reads %q", key)
		}
		require.NoError(t, fx.as.IsPutPermitted(info, []byte("any")), "root writes as well")
	})
}

// TestZZV529PreviewIsReadOnly proves the preview leaves the authorization
// configuration, the revision, the permission cache and the tokens untouched.
func TestZZV529PreviewIsReadOnly(t *testing.T) {
	fx := zzv529NewStore(t)
	zzv529AddRole(t, fx.as, "r1")
	zzv529AddUser(t, fx.as, "u1")
	zzv529BindRole(t, fx.as, "u1", "r1")

	revisionBefore := fx.as.Revision()
	roleBefore, err := fx.as.RoleGet(&pb.AuthRoleGetRequest{Role: "r1"})
	require.NoError(t, err)
	userBefore, err := fx.as.UserGet(&pb.AuthUserGetRequest{Name: "u1"})
	require.NoError(t, err)

	changes := []*PermissionPreviewChange{
		zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
		zzv529GrantPermChange("r1", authpb.Permission_WRITE, []byte("d"), []byte("e")),
		zzv529GrantRoleChange("u1", "root"),
	}

	for attempt := 0; attempt < 3; attempt++ {
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		require.NotEmpty(t, result.Users)
		require.Equal(t, revisionBefore, result.AuthRevision)
	}

	assert.Equal(t, revisionBefore, fx.as.Revision(), "the auth revision must not move")

	roleAfter, err := fx.as.RoleGet(&pb.AuthRoleGetRequest{Role: "r1"})
	require.NoError(t, err)
	assert.Empty(t, roleAfter.Perm, "no permission may be written")
	assert.Equal(t, roleBefore.Perm, roleAfter.Perm)

	userAfter, err := fx.as.UserGet(&pb.AuthUserGetRequest{Name: "u1"})
	require.NoError(t, err)
	assert.Equal(t, userBefore.Roles, userAfter.Roles, "role membership must not change")
	assert.NotContains(t, userAfter.Roles, "root")

	// The existing token of a real authenticated user must still be valid.
	info, err := fx.as.AuthInfoFromCtx(zzv529TokenContext(t, fx.adminToken))
	require.NoError(t, err)
	assert.Equal(t, "admin", info.Username, "the token must not be invalidated by a preview")

	// Data access is unchanged for the affected user.
	probe := &AuthInfo{Username: "u1", Revision: fx.as.Revision()}
	require.Error(t, fx.as.IsRangePermitted(probe, []byte("a"), []byte("c")),
		"the preview must not grant the previewed read interval")
	require.Error(t, fx.as.IsPutPermitted(probe, []byte("d")),
		"the preview must not grant the previewed write interval")

	// The invalid case must not leave a partial result behind either.
	bad := append(append([]*PermissionPreviewChange{}, changes...),
		zzv529GrantPermChange("does-not-exist", authpb.Permission_READ, []byte("k"), nil))
	failed, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, bad)
	require.Error(t, err)
	assert.Nil(t, failed, "a failed preview must not return a partial result")
	assert.Equal(t, revisionBefore, fx.as.Revision())
}

// TestZZV529InvalidChangesAreAtomicAndTyped checks the error contract.
func TestZZV529InvalidChangesAreAtomicAndTyped(t *testing.T) {
	fx := zzv529NewStore(t)
	zzv529AddRole(t, fx.as, "r1")
	zzv529AddRole(t, fx.as, "other")
	zzv529AddUser(t, fx.as, "u1")
	zzv529BindRole(t, fx.as, "u1", "r1")
	zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("a"), []byte("c"))

	validFirst := zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("d"), []byte("e"))

	cases := []struct {
		name    string
		changes []*PermissionPreviewChange
		want    error
	}{
		{"unknown role", []*PermissionPreviewChange{validFirst, zzv529GrantPermChange("ghost", authpb.Permission_READ, []byte("k"), nil)}, ErrRoleNotFound},
		{"unknown user", []*PermissionPreviewChange{validFirst, zzv529GrantRoleChange("ghost", "r1")}, ErrUserNotFound},
		{"role not granted", []*PermissionPreviewChange{validFirst, zzv529RevokeRoleChange("u1", "other")}, ErrRoleNotGranted},
		{"permission not granted", []*PermissionPreviewChange{validFirst, zzv529RevokePermChange("r1", []byte("x"), []byte("y"))}, ErrPermissionNotGranted},
		{"permission without value", []*PermissionPreviewChange{validFirst, {Type: PermissionPreviewRoleGrantPermission, Role: "r1"}}, ErrPermissionNotGiven},
		{"empty key", []*PermissionPreviewChange{validFirst, zzv529GrantPermChange("r1", authpb.Permission_READ, nil, nil)}, ErrInvalidAuthMgmt},
		{"unknown change type", []*PermissionPreviewChange{validFirst, {Type: PermissionPreviewChangeType(99), Role: "r1"}}, ErrInvalidAuthMgmt},
		{"nil change", []*PermissionPreviewChange{validFirst, nil}, ErrInvalidAuthMgmt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			revisionBefore := fx.as.Revision()
			result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, tc.changes)
			require.Error(t, err)
			assert.Nil(t, result, "no partial result may be published")
			assert.ErrorIs(t, err, tc.want, "the cause must stay unwrappable")

			var invalid *PermissionPreviewInvalidChangeError
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, 1, invalid.Index, "the offending change index must be reported")
			assert.Equal(t, revisionBefore, fx.as.Revision())
		})
	}

	t.Run("first change invalid is reported at index zero", func(t *testing.T) {
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root,
			[]*PermissionPreviewChange{zzv529GrantPermChange("ghost", authpb.Permission_READ, []byte("k"), nil)})
		require.Error(t, err)
		assert.Nil(t, result)
		var invalid *PermissionPreviewInvalidChangeError
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, 0, invalid.Index)
	})

	t.Run("a valid sequence is accepted in order", func(t *testing.T) {
		// Grant a role then use it in the next change: order matters and must
		// be simulated sequentially.
		changes := []*PermissionPreviewChange{
			zzv529GrantPermChange("other", authpb.Permission_READ, []byte("m"), []byte("n")),
			zzv529GrantRoleChange("u1", "other"),
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		change := zzv529UserChange(t, result, "u1")
		require.Len(t, change.ReadAdded, 1)
		assert.Equal(t, []byte("m"), change.ReadAdded[0].Key)
	})

	t.Run("revoking a role that was granted earlier in the same request", func(t *testing.T) {
		changes := []*PermissionPreviewChange{
			zzv529GrantRoleChange("u1", "other"),
			zzv529RevokeRoleChange("u1", "other"),
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
		assert.Empty(t, result.Users, "the net effect is nil, so no user is affected")
	})
}

// TestZZV529ObservationPointAndLimits covers cancellation, the "old revision"
// guard and the configured limits.
func TestZZV529ObservationPointAndLimits(t *testing.T) {
	fx := zzv529NewStore(t)
	zzv529AddRole(t, fx.as, "r1")
	zzv529AddUser(t, fx.as, "u1")
	zzv529BindRole(t, fx.as, "u1", "r1")

	t.Run("cancelled request fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := fx.as.PreviewPermissionChanges(ctx, fx.root,
			[]*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c"))})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, result)
	})

	t.Run("too many changes", func(t *testing.T) {
		changes := make([]*PermissionPreviewChange, 0, permissionPreviewMaxChanges+1)
		for i := 0; i <= permissionPreviewMaxChanges; i++ {
			changes = append(changes, zzv529GrantPermChange("r1", authpb.Permission_READ, []byte(fmt.Sprintf("k%04d", i)), nil))
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPermissionPreviewTooManyChanges)
		assert.Nil(t, result)

		// The limit itself is still accepted.
		ok := make([]*PermissionPreviewChange, 0, permissionPreviewMaxChanges)
		for i := 0; i < permissionPreviewMaxChanges; i++ {
			ok = append(ok, zzv529GrantPermChange("r1", authpb.Permission_READ, []byte(fmt.Sprintf("k%04d", i)), nil))
		}
		result, err = fx.as.PreviewPermissionChanges(context.Background(), fx.root, ok)
		require.NoError(t, err)
		require.Len(t, result.Users, 1)
	})

	t.Run("too many affected users", func(t *testing.T) {
		// One shared role granted to more users than the configured limit.
		zzv529AddRole(t, fx.as, "shared")
		for i := 0; i <= permissionPreviewMaxAffectedUsers; i++ {
			name := fmt.Sprintf("bulk-%03d", i)
			zzv529AddUser(t, fx.as, name)
			zzv529BindRole(t, fx.as, name, "shared")
		}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root,
			[]*PermissionPreviewChange{zzv529GrantPermChange("shared", authpb.Permission_READ, []byte("a"), []byte("z"))})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPermissionPreviewTooManyAffectedUsers)
		assert.Nil(t, result)
	})

	t.Run("too many result ranges", func(t *testing.T) {
		fx2 := zzv529NewStore(t)
		zzv529AddRole(t, fx2.as, "spread")
		zzv529AddUser(t, fx2.as, "u2")
		zzv529BindRole(t, fx2.as, "u2", "spread")
		// Disjoint intervals never merge, so the result exceeds the range limit.
		changes := make([]*PermissionPreviewChange, 0, 64)
		for i := 0; i < 64; i++ {
			changes = append(changes, zzv529GrantPermChange("spread", authpb.Permission_READ,
				[]byte(fmt.Sprintf("k%06d", i*2)), []byte(fmt.Sprintf("k%06d", i*2+1))))
		}
		saved := permissionPreviewMaxRanges
		permissionPreviewMaxRanges = 16
		defer func() { permissionPreviewMaxRanges = saved }()

		result, err := fx2.as.PreviewPermissionChanges(context.Background(), fx2.root, changes)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPermissionPreviewResultTooLarge)
		assert.Nil(t, result)
	})

	t.Run("concurrent permission update invalidates the observation point", func(t *testing.T) {
		fx3 := zzv529NewStore(t)
		zzv529AddRole(t, fx3.as, "r1")
		zzv529AddUser(t, fx3.as, "u1")
		zzv529BindRole(t, fx3.as, "u1", "r1")

		result, err := fx3.as.PreviewPermissionChanges(context.Background(), fx3.root,
			[]*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c"))})
		require.NoError(t, err, "the first preview must succeed")
		require.NotEmpty(t, result.Users)

		// A concurrent update moves the revision; the next preview must either
		// observe the new revision or fail with the retryable error.
		_, err = fx3.as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
			Name: "r1", Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("z"), RangeEnd: nil},
		})
		require.NoError(t, err)
		require.Greater(t, fx3.as.Revision(), result.AuthRevision)

		retried, err := fx3.as.PreviewPermissionChanges(context.Background(), fx3.root,
			[]*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("b"), []byte("d"))})
		require.NoError(t, err)
		assert.Equal(t, fx3.as.Revision(), retried.AuthRevision,
			"the new observation point must report the new revision")

		// The preview itself must never be the reason for an invalidated
		// observation point: running it repeatedly keeps succeeding.
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := fx3.as.PreviewPermissionChanges(context.Background(), fx3.root,
					[]*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("q"), []byte("r"))})
				assert.NoError(t, err)
			}()
		}
		wg.Wait()
		time.Sleep(10 * time.Millisecond)
	})
}

// TestZZV529AdministratorsOnly verifies the management-only restriction.
func TestZZV529AdministratorsOnly(t *testing.T) {
	fx := zzv529NewStore(t)
	zzv529AddRole(t, fx.as, "r1")
	zzv529AddUser(t, fx.as, "u1")
	zzv529BindRole(t, fx.as, "u1", "r1")
	zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("a"), []byte("b"))

	changes := []*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("c"), []byte("d"))}

	t.Run("root is accepted", func(t *testing.T) {
		_, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
		require.NoError(t, err)
	})

	t.Run("another root holder is accepted", func(t *testing.T) {
		_, err := fx.as.PreviewPermissionChanges(context.Background(), fx.adminInfo, changes)
		require.NoError(t, err)
	})

	t.Run("an ordinary user is rejected", func(t *testing.T) {
		info := &AuthInfo{Username: "u1", Revision: fx.as.Revision()}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), info, changes)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPermissionDenied)
		assert.Nil(t, result)
	})

	t.Run("an unknown caller is rejected", func(t *testing.T) {
		info := &AuthInfo{Username: "ghost", Revision: fx.as.Revision()}
		result, err := fx.as.PreviewPermissionChanges(context.Background(), info, changes)
		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("no caller is rejected while auth is enabled", func(t *testing.T) {
		result, err := fx.as.PreviewPermissionChanges(context.Background(), nil, changes)
		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("no caller is accepted while auth is disabled", func(t *testing.T) {
		fx2 := zzv529NewStore(t)
		zzv529AddRole(t, fx2.as, "r1")
		zzv529AddUser(t, fx2.as, "u1")
		zzv529BindRole(t, fx2.as, "u1", "r1")
		fx2.as.AuthDisable()
		assert.False(t, fx2.as.IsAuthEnabled())

		result, err := fx2.as.PreviewPermissionChanges(context.Background(), nil,
			[]*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c"))})
		require.NoError(t, err)
		require.Len(t, result.Users, 1)
		assert.Equal(t, "u1", result.Users[0].User)
	})
}

// TestZZV529ResultsAreNormalizedAndStable checks the ordering guarantees.
func TestZZV529ResultsAreNormalizedAndStable(t *testing.T) {
	fx := zzv529NewStore(t)
	zzv529AddRole(t, fx.as, "r1")
	zzv529AddUser(t, fx.as, "zeta")
	zzv529AddUser(t, fx.as, "alpha")
	zzv529BindRole(t, fx.as, "zeta", "r1")
	zzv529BindRole(t, fx.as, "alpha", "r1")

	// The preview is computed without applying anything, so the fixture has to
	// be reachable through the same public API first.
	roleBeforeApply, err := fx.as.RoleGet(&pb.AuthRoleGetRequest{Role: "r1"})
	require.NoError(t, err)
	userBeforeApply, err := fx.as.UserGet(&pb.AuthUserGetRequest{Name: "alpha"})
	require.NoError(t, err)
	t.Logf("before apply: r1 perms=%v; alpha roles=%v; revision=%d",
		roleBeforeApply.Perm, userBeforeApply.Roles, fx.as.Revision())

	// Adjacent and overlapping intervals must be merged into one.
	changes := []*PermissionPreviewChange{
		zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("d"), []byte("f")),
		zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
		zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("c"), []byte("e")),
		zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("b"), []byte("d")),
	}
	result, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
	require.NoError(t, err)

	var names []string
	for _, u := range result.Users {
		names = append(names, u.User)
	}
	assert.Equal(t, []string{"alpha", "zeta"}, names, "users must be stably sorted by name")

	for _, u := range result.Users {
		t.Logf("user %s added=%s", u.User, zzv529DescribeRanges(u.ReadAdded))
		require.Len(t, u.ReadAdded, 1, "overlapping and adjacent intervals must merge")
		assert.Equal(t, []byte("a"), u.ReadAdded[0].Key)
		assert.Equal(t, []byte("f"), u.ReadAdded[0].RangeEnd)
		require.Len(t, u.ReadAfter, 1)
	}

	// Repeating the same request must produce the same intervals.
	again, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, changes)
	require.NoError(t, err)
	require.Equal(t, len(result.Users), len(again.Users))
	for i := range result.Users {
		assert.Equal(t, zzv529DescribeRanges(result.Users[i].ReadAdded),
			zzv529DescribeRanges(again.Users[i].ReadAdded))
		assert.Equal(t, zzv529DescribeRanges(result.Users[i].ReadAfter),
			zzv529DescribeRanges(again.Users[i].ReadAfter))
	}

	// Apply the merged changes so that the effective intervals become [a,f),
	// then check the preview no longer reports an already covered grant.
	zzv529ApplyToStore(t, fx.as, changes)
	roleAfterApply, err := fx.as.RoleGet(&pb.AuthRoleGetRequest{Role: "r1"})
	require.NoError(t, err)
	t.Logf("after apply: r1 perms=%v; revision=%d", roleAfterApply.Perm, fx.as.Revision())
	require.NotEmpty(t, roleAfterApply.Perm)

	// A grant that is already covered by the effective intervals must not be
	// reported: [b,e) is inside the merged [a,f), so no user's effective access
	// changes and the preview must list nobody.
	noop := []*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("b"), []byte("e"))}
	noopResult, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, noop)
	require.NoError(t, err)
	for _, u := range noopResult.Users {
		t.Logf("absorbed-change report: user=%s readBefore=%s readAfter=%s readAdded=%s readRevoked=%s",
			u.User, zzv529DescribeRanges(u.ReadBefore), zzv529DescribeRanges(u.ReadAfter),
			zzv529DescribeRanges(u.ReadAdded), zzv529DescribeRanges(u.ReadRevoked))
	}
	assert.Empty(t, noopResult.Users,
		"a change absorbed by the already effective intervals affects nobody")

	// A grant that extends the covered set does affect the users.
	extending := []*PermissionPreviewChange{zzv529GrantPermChange("r1", authpb.Permission_READ, []byte("f"), []byte("h"))}
	extendingResult, err := fx.as.PreviewPermissionChanges(context.Background(), fx.root, extending)
	require.NoError(t, err)
	require.Len(t, extendingResult.Users, 2)
	for _, u := range extendingResult.Users {
		require.Len(t, u.ReadAdded, 1)
		assert.Equal(t, []byte("f"), u.ReadAdded[0].Key)
		assert.Equal(t, []byte("h"), u.ReadAdded[0].RangeEnd)
	}
}

// TestZZV529ExistingBehaviourUnchanged is the compatibility check for the
// authorization paths the feature must not touch.
func TestZZV529ExistingBehaviourUnchanged(t *testing.T) {
	fx := zzv529NewStore(t)
	zzv529AddRole(t, fx.as, "r1")
	zzv529AddUser(t, fx.as, "u1")
	zzv529BindRole(t, fx.as, "u1", "r1")
	zzv529ApplyPerm(t, fx.as, "r1", authpb.Permission_READ, []byte("a"), []byte("c"))

	// The ordinary management APIs keep working and keep moving the revision.
	before := fx.as.Revision()
	_, err := fx.as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "r1", Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("x"), RangeEnd: []byte("y")},
	})
	require.NoError(t, err)
	assert.Greater(t, fx.as.Revision(), before, "a real change must move the revision")

	info := &AuthInfo{Username: "u1", Revision: fx.as.Revision()}
	require.NoError(t, fx.as.IsRangePermitted(info, []byte("a"), []byte("c")))
	require.NoError(t, fx.as.IsRangePermitted(info, []byte("x"), []byte("y")))
	require.Error(t, fx.as.IsRangePermitted(info, []byte("m"), nil))
	require.Error(t, fx.as.IsPutPermitted(info, []byte("a")), "read permission still does not allow writes")

	// Token issuance and validation still follow the revision.
	authCtx := zzv529AuthContext("zzv529-compat-issue")
	token, err := fx.as.Authenticate(authCtx, "admin", "admin-pass")
	require.NoError(t, err)
	ctx := zzv529TokenContext(t, token.Token)
	authInfo, err := fx.as.AuthInfoFromCtx(ctx)
	require.NoError(t, err)
	assert.Equal(t, "admin", authInfo.Username)

	// Password verification still happens through CheckPassword and rejects a
	// wrong secret.
	_, err = fx.as.CheckPassword("admin", "wrong")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthFailed)
	revision, err := fx.as.CheckPassword("admin", "admin-pass")
	require.NoError(t, err)
	assert.Equal(t, fx.as.Revision(), revision)

	// The public API still rejects a user that may not authenticate.
	_, err = fx.as.Authenticate(zzv529AuthContext("zzv529-compat-nopass"), "u1", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthFailed)
}

// zzv529AuthContext builds the request-scoped context Authenticate expects.
// A distinct token prefix per call is required: simple tokens must never be
// reassigned to the same prefix.
func zzv529AuthContext(prefix string) context.Context {
	return context.WithValue(
		context.WithValue(context.Background(), AuthenticateParamIndex{}, uint64(1)),
		AuthenticateParamSimpleTokenPrefix{}, prefix)
}

// zzv529TokenContext builds an incoming gRPC context carrying a bearer token
// the same way the gRPC interceptor does.
func zzv529TokenContext(t *testing.T, token string) context.Context {
	t.Helper()
	md := metadata.New(map[string]string{rpctypes.TokenFieldNameGRPC: "Bearer " + token})
	return metadata.NewIncomingContext(t.Context(), md)
}

var _ = errors.Is
