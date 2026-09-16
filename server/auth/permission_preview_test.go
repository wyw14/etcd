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

	"go.etcd.io/etcd/api/v3/authpb"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
)

// newPreviewAuthStore builds an enabled auth store backed by the in-memory
// mock, with the root user/role and returns a root AuthInfo for previews.
func newPreviewAuthStore(t *testing.T) (AuthStore, *AuthInfo) {
	t.Helper()
	tp, err := NewTokenProvider(zaptest.NewLogger(t), tokenTypeSimple, dummyIndexWaiter, simpleTokenTTLDefault)
	require.NoError(t, err)
	as := NewAuthStore(zaptest.NewLogger(t), newBackendMock(), tp, bcrypt.MinCost)
	t.Cleanup(func() { require.NoError(t, as.Close()) })
	require.NoError(t, enableAuthAndCreateRoot(as))

	return as, &AuthInfo{Username: rootUser, Revision: as.Revision()}
}

func grantPermChange(role string, typ authpb.Permission_Type, key, rangeEnd []byte) *PermissionPreviewChange {
	return &PermissionPreviewChange{
		Type: PermissionPreviewRoleGrantPermission,
		Role: role,
		Perm: &authpb.Permission{PermType: typ, Key: key, RangeEnd: rangeEnd},
	}
}

func revokePermChange(role string, key, rangeEnd []byte) *PermissionPreviewChange {
	return &PermissionPreviewChange{
		Type: PermissionPreviewRoleRevokePermission,
		Role: role,
		Perm: &authpb.Permission{Key: key, RangeEnd: rangeEnd},
	}
}

func grantRoleChange(user, role string) *PermissionPreviewChange {
	return &PermissionPreviewChange{Type: PermissionPreviewUserGrantRole, User: user, Role: role}
}

func revokeRoleChange(user, role string) *PermissionPreviewChange {
	return &PermissionPreviewChange{Type: PermissionPreviewUserRevokeRole, User: user, Role: role}
}

// expectedRange uses strings for readable test expectations: a nil wantEnd
// means single key (nil range end), "\x00" means an open-ended range.
type expectedRange struct {
	key, end string
}

func requireRanges(t *testing.T, got []PermissionPreviewRange, want ...expectedRange) {
	t.Helper()
	if len(want) == 0 {
		assert.Empty(t, got)
		return
	}
	require.Len(t, got, len(want))
	for i, w := range want {
		assert.Equalf(t, []byte(w.key), got[i].Key, "range %d key mismatch", i)
		var wantEnd []byte
		if w.end != "" || len(w.key) == 0 {
			wantEnd = []byte(w.end)
		}
		assert.Equalf(t, wantEnd, got[i].RangeEnd, "range %d end mismatch", i)
	}
}

func findUserChange(t *testing.T, result *PermissionPreviewResult, user string) *PermissionPreviewUserChange {
	t.Helper()
	for i := range result.Users {
		if result.Users[i].User == user {
			return &result.Users[i]
		}
	}
	require.Failf(t, "user not found in preview result", "user %q, result %+v", user, result.Users)
	return nil
}

func TestPermissionPreviewRoleGrantAndRevoke(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
	require.NoError(t, err)

	// grant a bounded read range through the preview
	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	assert.Equal(t, as.Revision(), result.AuthRevision)
	uc := &result.Users[0]
	assert.Equal(t, "u1", uc.User)
	requireRanges(t, uc.ReadAdded, expectedRange{"a", "c"})
	requireRanges(t, uc.ReadAfter, expectedRange{"a", "c"})
	requireRanges(t, uc.ReadBefore)
	requireRanges(t, uc.ReadRevoked)
	requireRanges(t, uc.WriteBefore)
	requireRanges(t, uc.WriteAfter)
	requireRanges(t, uc.WriteAdded)
	requireRanges(t, uc.WriteRevoked)

	// actually apply the grant, then preview the revocation
	_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "r1",
		Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("a"), RangeEnd: []byte("c")},
	})
	require.NoError(t, err)

	result, err = as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		revokePermChange("r1", []byte("a"), []byte("c")),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	uc = &result.Users[0]
	requireRanges(t, uc.ReadRevoked, expectedRange{"a", "c"})
	requireRanges(t, uc.ReadBefore, expectedRange{"a", "c"})
	requireRanges(t, uc.ReadAfter)
	requireRanges(t, uc.ReadAdded)
}

func TestPermissionPreviewOverlappingRoles(t *testing.T) {
	as, root := newPreviewAuthStore(t)

	for _, name := range []string{"r1", "r2"} {
		_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: name})
		require.NoError(t, err)
	}
	_, err := as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	for _, role := range []string{"r1", "r2"} {
		_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: role})
		require.NoError(t, err)
	}
	// r1 covers [a, e), r2 covers [c, g)
	for _, c := range []struct {
		role     string
		key, end string
	}{
		{"r1", "a", "e"}, {"r2", "c", "g"},
	} {
		_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
			Name: c.role,
			Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte(c.key), RangeEnd: []byte(c.end)},
		})
		require.NoError(t, err)
	}

	// revoking only r1 must not report [c, e) as lost: r2 still covers it
	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		revokePermChange("r1", []byte("a"), []byte("e")),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	uc := &result.Users[0]
	requireRanges(t, uc.ReadBefore, expectedRange{"a", "g"})
	requireRanges(t, uc.ReadAfter, expectedRange{"c", "g"})
	requireRanges(t, uc.ReadRevoked, expectedRange{"a", "c"})
	requireRanges(t, uc.ReadAdded)

	// revoking both roles loses the entire merged range
	result, err = as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		revokePermChange("r1", []byte("a"), []byte("e")),
		revokePermChange("r2", []byte("c"), []byte("g")),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	requireRanges(t, result.Users[0].ReadRevoked, expectedRange{"a", "g"})
	requireRanges(t, result.Users[0].ReadAfter)
}

func TestPermissionPreviewUserRoleMembership(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "r1",
		Perm: &authpb.Permission{PermType: authpb.Permission_READWRITE, Key: []byte("k")},
	})
	require.NoError(t, err)

	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantRoleChange("u1", "r1"),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	uc := &result.Users[0]
	requireRanges(t, uc.ReadAdded, expectedRange{"k", ""})
	requireRanges(t, uc.WriteAdded, expectedRange{"k", ""})

	// apply for real, then preview the role revocation
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
	require.NoError(t, err)
	result, err = as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		revokeRoleChange("u1", "r1"),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	requireRanges(t, result.Users[0].ReadRevoked, expectedRange{"k", ""})
	requireRanges(t, result.Users[0].WriteRevoked, expectedRange{"k", ""})
}

func TestPermissionPreviewRangeKinds(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	for _, name := range []string{"single", "prefix", "bounded"} {
		_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: name})
		require.NoError(t, err)
	}
	for _, name := range []string{"u-single", "u-prefix", "u-bounded", "u-root"} {
		_, err := as.UserAdd(&pb.AuthUserAddRequest{Name: name, Options: &authpb.UserAddOptions{NoPassword: true}})
		require.NoError(t, err)
	}
	_, err := as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "single",
		Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("k")},
	})
	require.NoError(t, err)
	_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "prefix",
		Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("pfx/"), RangeEnd: []byte{0}},
	})
	require.NoError(t, err)
	_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "bounded",
		Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("a"), RangeEnd: []byte("c")},
	})
	require.NoError(t, err)

	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantRoleChange("u-single", "single"),
		grantRoleChange("u-prefix", "prefix"),
		grantRoleChange("u-bounded", "bounded"),
		grantRoleChange("u-root", rootRole),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 4)
	// users are stably sorted by name
	assert.Equal(t, []string{"u-bounded", "u-prefix", "u-root", "u-single"},
		[]string{result.Users[0].User, result.Users[1].User, result.Users[2].User, result.Users[3].User})

	uc := findUserChange(t, result, "u-single")
	requireRanges(t, uc.ReadAdded, expectedRange{"k", ""})
	uc = findUserChange(t, result, "u-prefix")
	requireRanges(t, uc.ReadAdded, expectedRange{"pfx/", "\x00"})
	uc = findUserChange(t, result, "u-bounded")
	requireRanges(t, uc.ReadAdded, expectedRange{"a", "c"})
	uc = findUserChange(t, result, "u-root")
	// the root role grants the whole key space for both read and write
	requireRanges(t, uc.ReadAdded, expectedRange{"\x00", "\x00"})
	requireRanges(t, uc.WriteAdded, expectedRange{"\x00", "\x00"})
}

func TestPermissionPreviewRootRoleRevocation(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "boss", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "boss", Role: rootRole})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "boss", Role: "r1"})
	require.NoError(t, err)
	_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "r1",
		Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("x"), RangeEnd: []byte("y")},
	})
	require.NoError(t, err)

	// revoking the root role leaves only r1's read range: everything else is
	// reported as lost, for both read and write
	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		revokeRoleChange("boss", rootRole),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	uc := &result.Users[0]
	requireRanges(t, uc.ReadBefore, expectedRange{"\x00", "\x00"})
	requireRanges(t, uc.WriteBefore, expectedRange{"\x00", "\x00"})
	requireRanges(t, uc.ReadAfter, expectedRange{"x", "y"})
	requireRanges(t, uc.WriteAfter)
	requireRanges(t, uc.ReadRevoked, expectedRange{"\x00", "x"}, expectedRange{"y", "\x00"})
	requireRanges(t, uc.WriteRevoked, expectedRange{"\x00", "\x00"})
	requireRanges(t, uc.ReadAdded)
	requireRanges(t, uc.WriteAdded)
}

func TestPermissionPreviewMergedAndSorted(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	for _, name := range []string{"r1", "r2"} {
		_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: name})
		require.NoError(t, err)
	}
	_, err := as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	for _, role := range []string{"r1", "r2"} {
		_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: role})
		require.NoError(t, err)
	}

	// existing perms before the preview: point "a" and [a\x00, c) merge into
	// [a, c); [c, e) is adjacent and joins; [z9, open-ended) stays separate
	grants := []struct {
		role     string
		key, end string
	}{
		{"r1", "a", ""},      // single key a
		{"r1", "a\x00", "c"}, // a\x00 .. c
		{"r2", "c", "e"},     // adjacent
		{"r2", "z9", "\x00"}, // open ended
	}
	for _, g := range grants {
		_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
			Name: g.role,
			Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte(g.key), RangeEnd: []byte(g.end)},
		})
		require.NoError(t, err)
	}

	// an overlapping extension and a range adjacent to the open-ended tail
	// must merge; unsorted input order must not change the stable output order
	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantPermChange("r1", authpb.Permission_READ, []byte("z"), []byte("z9")),
		grantPermChange("r1", authpb.Permission_READ, []byte("d"), []byte("f")),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	uc := &result.Users[0]
	// before: [a, e), [z9, open)
	requireRanges(t, uc.ReadBefore, expectedRange{"a", "e"}, expectedRange{"z9", "\x00"})
	// after: [a, f), and [z, z9) joins the open-ended tail at z9
	requireRanges(t, uc.ReadAfter, expectedRange{"a", "f"}, expectedRange{"z", "\x00"})
	requireRanges(t, uc.ReadAdded, expectedRange{"e", "f"}, expectedRange{"z", "z9"})
	requireRanges(t, uc.ReadRevoked)
}

func TestPermissionPreviewPermissionTypeChanges(t *testing.T) {
	cases := []struct {
		name          string
		before, after authpb.Permission_Type
		readAdded     bool
		readRevoked   bool
		writeAdded    bool
		writeRevoked  bool
	}{
		{"READWRITE to READ", authpb.Permission_READWRITE, authpb.Permission_READ, false, false, false, true},
		{"READWRITE to WRITE", authpb.Permission_READWRITE, authpb.Permission_WRITE, false, true, false, false},
		{"READ to READWRITE", authpb.Permission_READ, authpb.Permission_READWRITE, false, false, true, false},
		{"WRITE to READWRITE", authpb.Permission_WRITE, authpb.Permission_READWRITE, true, false, false, false},
		{"READ to WRITE", authpb.Permission_READ, authpb.Permission_WRITE, false, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			as, root := newPreviewAuthStore(t)
			_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
			require.NoError(t, err)
			_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
			require.NoError(t, err)
			_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
			require.NoError(t, err)
			_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
				Name: "r1",
				Perm: &authpb.Permission{PermType: tc.before, Key: []byte("a"), RangeEnd: []byte("c")},
			})
			require.NoError(t, err)

			result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
				grantPermChange("r1", tc.after, []byte("a"), []byte("c")),
			})
			require.NoError(t, err)
			require.Len(t, result.Users, 1)
			uc := &result.Users[0]
			if tc.readAdded {
				requireRanges(t, uc.ReadAdded, expectedRange{"a", "c"})
			} else {
				requireRanges(t, uc.ReadAdded)
			}
			if tc.readRevoked {
				requireRanges(t, uc.ReadRevoked, expectedRange{"a", "c"})
			} else {
				requireRanges(t, uc.ReadRevoked)
			}
			if tc.writeAdded {
				requireRanges(t, uc.WriteAdded, expectedRange{"a", "c"})
			} else {
				requireRanges(t, uc.WriteAdded)
			}
			if tc.writeRevoked {
				requireRanges(t, uc.WriteRevoked, expectedRange{"a", "c"})
			} else {
				requireRanges(t, uc.WriteRevoked)
			}
		})
	}
}

func TestPermissionPreviewSeparateReadWriteGrants(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	// on a single role, a second grant on the same range replaces the
	// permission type, matching RoleGrantPermission semantics
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
		grantPermChange("r1", authpb.Permission_WRITE, []byte("a"), []byte("c")),
	})
	require.NoError(t, err)
	require.Empty(t, result.Users, "role r1 is not granted to any user yet")

	// READ and WRITE granted separately on the same range but on different
	// roles compose into READWRITE for the member of both roles
	_, err = as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r2"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r2"})
	require.NoError(t, err)

	result, err = as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
		grantPermChange("r2", authpb.Permission_WRITE, []byte("a"), []byte("c")),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	uc := &result.Users[0]
	requireRanges(t, uc.ReadAdded, expectedRange{"a", "c"})
	requireRanges(t, uc.WriteAdded, expectedRange{"a", "c"})
}

func TestPermissionPreviewInvalidChanges(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
	require.NoError(t, err)
	_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "r1",
		Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("a"), RangeEnd: []byte("c")},
	})
	require.NoError(t, err)

	revisionBefore := as.Revision()

	cases := []struct {
		name    string
		changes []*PermissionPreviewChange
		index   int
		wantErr error
	}{
		{
			name:    "grant to unknown role",
			changes: []*PermissionPreviewChange{grantPermChange("nope", authpb.Permission_READ, []byte("a"), []byte("c"))},
			index:   0,
			wantErr: ErrRoleNotFound,
		},
		{
			name:    "grant invalid range",
			changes: []*PermissionPreviewChange{grantPermChange("r1", authpb.Permission_READ, nil, []byte("c"))},
			index:   0,
			wantErr: ErrInvalidAuthMgmt,
		},
		{
			name:    "grant without permission",
			changes: []*PermissionPreviewChange{{Type: PermissionPreviewRoleGrantPermission, Role: "r1"}},
			index:   0,
			wantErr: ErrPermissionNotGiven,
		},
		{
			name:    "revoke not granted permission",
			changes: []*PermissionPreviewChange{revokePermChange("r1", []byte("x"), []byte("z"))},
			index:   0,
			wantErr: ErrPermissionNotGranted,
		},
		{
			name:    "revoke from unknown role",
			changes: []*PermissionPreviewChange{revokePermChange("nope", []byte("a"), []byte("c"))},
			index:   0,
			wantErr: ErrRoleNotFound,
		},
		{
			name:    "grant role to unknown user",
			changes: []*PermissionPreviewChange{grantRoleChange("nope", "r1")},
			index:   0,
			wantErr: ErrUserNotFound,
		},
		{
			name:    "grant unknown role to user",
			changes: []*PermissionPreviewChange{grantRoleChange("u1", "nope")},
			index:   0,
			wantErr: ErrRoleNotFound,
		},
		{
			name:    "revoke role not granted to user",
			changes: []*PermissionPreviewChange{revokeRoleChange("u1", "nope")},
			index:   0,
			wantErr: ErrRoleNotGranted,
		},
		{
			name:    "revoke root role from root user",
			changes: []*PermissionPreviewChange{revokeRoleChange(rootUser, rootRole)},
			index:   0,
			wantErr: ErrInvalidAuthMgmt,
		},
		{
			name:    "unknown change type",
			changes: []*PermissionPreviewChange{{Type: PermissionPreviewChangeType(99), User: "u1", Role: "r1"}},
			index:   0,
			wantErr: ErrInvalidAuthMgmt,
		},
		{
			name:    "nil change",
			changes: []*PermissionPreviewChange{nil},
			index:   0,
			wantErr: ErrInvalidAuthMgmt,
		},
		{
			name: "invalid change after valid changes is reported with its index",
			changes: []*PermissionPreviewChange{
				grantPermChange("r1", authpb.Permission_READ, []byte("p"), []byte("q")),
				grantRoleChange("u1", "r1"), // duplicate grant, a no-op
				revokePermChange("r1", []byte("zzz"), nil),
			},
			index:   2,
			wantErr: ErrPermissionNotGranted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := as.PreviewPermissionChanges(context.Background(), root, tc.changes)
			require.Error(t, err)
			assert.Nil(t, result, "invalid previews must not return partial results")
			var icErr *PermissionPreviewInvalidChangeError
			require.ErrorAs(t, err, &icErr)
			assert.Equal(t, tc.index, icErr.Index)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}

	// nothing was written and the observation revision is unchanged
	assert.Equal(t, revisionBefore, as.Revision())
}

func TestPermissionPreviewDoesNotMutateState(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
	require.NoError(t, err)

	revisionBefore := as.Revision()
	userAI := &AuthInfo{Username: "u1", Revision: as.Revision()}

	// the preview grants broad access, but it must not take effect
	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantPermChange("r1", authpb.Permission_READWRITE, []byte("secret"), nil),
	})
	require.NoError(t, err)
	require.Len(t, result.Users, 1)

	assert.Equal(t, revisionBefore, as.Revision(), "preview must not bump the auth revision")

	// the user still has no access to the previewed key
	assert.ErrorIs(t, as.IsPutPermitted(userAI, []byte("secret")), ErrPermissionDenied)
	assert.ErrorIs(t, as.IsRangePermitted(userAI, []byte("secret"), nil), ErrPermissionDenied)

	// and the role itself is still empty
	roleResp, err := as.RoleGet(&pb.AuthRoleGetRequest{Role: "r1"})
	require.NoError(t, err)
	assert.Empty(t, roleResp.Perm)
}

func TestPermissionPreviewEmptyAndNoOpChanges(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
	require.NoError(t, err)

	// empty request is a valid, empty preview at the current observation point
	result, err := as.PreviewPermissionChanges(context.Background(), root, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, as.Revision(), result.AuthRevision)
	assert.Empty(t, result.Users)

	// duplicate role grant is a no-op and must not report any change
	result, err = as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantRoleChange("u1", "r1"),
	})
	require.NoError(t, err)
	assert.Empty(t, result.Users)

	// the root user keeps full access regardless of changes to other roles
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: rootUser, Role: "r1"})
	require.NoError(t, err)
	result, err = as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		grantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
	})
	require.NoError(t, err)
	for _, uc := range result.Users {
		assert.NotEqual(t, rootUser, uc.User)
	}
}

func TestPermissionPreviewAdminOnly(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	changes := []*PermissionPreviewChange{grantRoleChange("u1", "r1")}

	// a non-root user is rejected
	_, err = as.PreviewPermissionChanges(context.Background(), &AuthInfo{Username: "u1"}, changes)
	assert.ErrorIs(t, err, ErrPermissionDenied)
	// missing identity is rejected while auth is enabled
	_, err = as.PreviewPermissionChanges(context.Background(), nil, changes)
	assert.ErrorIs(t, err, ErrUserEmpty)
	// root is accepted
	_, err = as.PreviewPermissionChanges(context.Background(), root, changes)
	require.NoError(t, err)

	// with auth disabled, no identity is required
	tp, err := NewTokenProvider(zaptest.NewLogger(t), tokenTypeSimple, dummyIndexWaiter, simpleTokenTTLDefault)
	require.NoError(t, err)
	disabled := NewAuthStore(zaptest.NewLogger(t), newBackendMock(), tp, bcrypt.MinCost)
	defer disabled.Close()
	_, err = disabled.PreviewPermissionChanges(context.Background(), nil, nil)
	require.NoError(t, err)
}

func TestPermissionPreviewCancelledContext(t *testing.T) {
	as, root := newPreviewAuthStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := as.PreviewPermissionChanges(ctx, root, []*PermissionPreviewChange{
		grantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
	})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)
}

// synchronizedMockBackend wraps the non-thread-safe backend mock with a
// RWMutex so that the preview read transaction and concurrent store updates
// can race safely. Locking mirrors the real backend semantics.
type synchronizedMockBackend struct {
	backendMock
	mu sync.RWMutex
}

type synchronizedMockTx struct {
	*txMock
	be *synchronizedMockBackend
}

func (b *synchronizedMockBackend) ReadTx() AuthReadTx {
	return &synchronizedMockTx{txMock: &txMock{be: &b.backendMock}, be: b}
}

func (b *synchronizedMockBackend) BatchTx() AuthBatchTx {
	return &synchronizedMockTx{txMock: &txMock{be: &b.backendMock}, be: b}
}

func (t *synchronizedMockTx) RLock()   { t.be.mu.RLock() }
func (t *synchronizedMockTx) RUnlock() { t.be.mu.RUnlock() }
func (t *synchronizedMockTx) Lock()    { t.be.mu.Lock() }
func (t *synchronizedMockTx) Unlock()  { t.be.mu.Unlock() }

func TestPermissionPreviewStaleObservation(t *testing.T) {
	tp, err := NewTokenProvider(zaptest.NewLogger(t), tokenTypeSimple, dummyIndexWaiter, simpleTokenTTLDefault)
	require.NoError(t, err)
	be := &synchronizedMockBackend{backendMock: *newBackendMock()}
	as := NewAuthStore(zaptest.NewLogger(t), be, tp, bcrypt.MinCost)
	defer as.Close()
	require.NoError(t, enableAuthAndCreateRoot(as))
	_, err = as.RoleAdd(&pb.AuthRoleAddRequest{Name: "mutator"})
	require.NoError(t, err)
	_, err = as.RoleAdd(&pb.AuthRoleAddRequest{Name: "target"})
	require.NoError(t, err)

	root := &AuthInfo{Username: rootUser, Revision: as.Revision()}
	changes := []*PermissionPreviewChange{
		grantPermChange("target", authpb.Permission_READ, []byte("a"), []byte("c")),
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// identical upserts still bump the auth revision
				_, _ = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
					Name: "mutator",
					Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("m")},
				})
			}
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	sawStale := false
	for time.Now().Before(deadline) && !sawStale {
		result, pErr := as.PreviewPermissionChanges(context.Background(), root, changes)
		if pErr == nil {
			assert.NotNil(t, result)
			continue
		}
		if errors.Is(pErr, ErrAuthOldRevision) {
			assert.Nil(t, result, "stale previews must not return results")
			sawStale = true
		} else {
			require.NoError(t, pErr)
		}
	}
	close(stop)
	wg.Wait()

	require.True(t, sawStale, "expected the observation point to be invalidated by concurrent updates")
}

func TestPermissionPreviewLimits(t *testing.T) {
	origChanges, origUsers, origRanges := permissionPreviewMaxChanges, permissionPreviewMaxAffectedUsers, permissionPreviewMaxRanges
	t.Cleanup(func() {
		permissionPreviewMaxChanges, permissionPreviewMaxAffectedUsers, permissionPreviewMaxRanges = origChanges, origUsers, origRanges
	})

	t.Run("too many changes", func(t *testing.T) {
		permissionPreviewMaxChanges = 2
		permissionPreviewMaxAffectedUsers = origUsers
		permissionPreviewMaxRanges = origRanges
		as, root := newPreviewAuthStore(t)
		_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
		require.NoError(t, err)
		var changes []*PermissionPreviewChange
		for i := 0; i < 3; i++ {
			changes = append(changes, grantPermChange("r1", authpb.Permission_READ, []byte{byte('a' + i)}, []byte{byte('b' + i)}))
		}
		result, err := as.PreviewPermissionChanges(context.Background(), root, changes)
		assert.ErrorIs(t, err, ErrPermissionPreviewTooManyChanges)
		assert.Nil(t, result)
	})

	t.Run("too many ranges", func(t *testing.T) {
		permissionPreviewMaxChanges = origChanges
		permissionPreviewMaxAffectedUsers = origUsers
		permissionPreviewMaxRanges = 10
		as, root := newPreviewAuthStore(t)
		_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "wide"})
		require.NoError(t, err)
		_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
		require.NoError(t, err)
		// 20 disjoint single-key grants exceed the range limit
		for i := 0; i < 20; i++ {
			_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
				Name: "wide",
				Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte{byte('a' + i), 0}},
			})
			require.NoError(t, err)
		}
		result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
			grantRoleChange("u1", "wide"),
		})
		assert.ErrorIs(t, err, ErrPermissionPreviewResultTooLarge)
		assert.Nil(t, result)
	})

	t.Run("too many affected users", func(t *testing.T) {
		permissionPreviewMaxChanges = origChanges
		permissionPreviewMaxAffectedUsers = 2
		permissionPreviewMaxRanges = origRanges
		as, root := newPreviewAuthStore(t)
		_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
		require.NoError(t, err)
		for i := 0; i < 3; i++ {
			name := fmt.Sprintf("u%d", i)
			_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: name, Options: &authpb.UserAddOptions{NoPassword: true}})
			require.NoError(t, err)
			_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: name, Role: "r1"})
			require.NoError(t, err)
		}
		result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
			grantPermChange("r1", authpb.Permission_READ, []byte("a"), []byte("c")),
		})
		assert.ErrorIs(t, err, ErrPermissionPreviewTooManyAffectedUsers)
		assert.Nil(t, result)
	})
}
