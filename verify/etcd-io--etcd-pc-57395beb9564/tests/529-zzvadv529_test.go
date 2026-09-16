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

// Adversarial acceptance checks for precheck 529.
//
// These tests start from the requirement text and try to falsify it: the
// reported 新增/撤销 ranges must equal the real change in effective access, and
// nothing may be reported when a caller's effective access does not change.

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/bcrypt"

	"go.etcd.io/etcd/api/v3/authpb"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
)

func zzvAdvStore(t *testing.T) (AuthStore, *AuthInfo) {
	t.Helper()
	tp, err := NewTokenProvider(zaptest.NewLogger(t), tokenTypeSimple, dummyIndexWaiter, simpleTokenTTLDefault)
	require.NoError(t, err)
	as := NewAuthStore(zaptest.NewLogger(t), newBackendMock(), tp, bcrypt.MinCost)
	t.Cleanup(func() { require.NoError(t, as.Close()) })
	require.NoError(t, enableAuthAndCreateRoot(as))
	return as, &AuthInfo{Username: "root", Revision: as.Revision()}
}

// zzvAdvEffectiveRanges reports the user's real effective read intervals by
// probing the real authorization path, independent of the preview's own model.
func zzvAdvEffectiveRanges(t *testing.T, as AuthStore, user string, keys [][]byte) []string {
	t.Helper()
	info := &AuthInfo{Username: user, Revision: as.Revision()}
	var allowed []string
	for _, key := range keys {
		if as.IsRangePermitted(info, key, nil) == nil {
			allowed = append(allowed, string(key))
		}
	}
	return allowed
}

// TestZZVAdv529GrantsCoveredByTheUnionAffectNobody checks the requirement that
// only users whose effective access actually changes are reported.
//
// A user's effective read access is the UNION of its roles' intervals. Adding a
// permission that is already contained in that union changes nothing, so the
// preview must not list the user as affected.
func TestZZVAdv529GrantsCoveredByTheUnionAffectNobody(t *testing.T) {
	as, root := zzvAdvStore(t)

	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "left"})
	require.NoError(t, err)
	_, err = as.RoleAdd(&pb.AuthRoleAddRequest{Name: "right"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "left"})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "right"})
	require.NoError(t, err)

	// left covers [a,c), right covers [c,e): the union is [a,e) with no gap.
	for _, spec := range []struct {
		role string
		key  []byte
		end  []byte
	}{
		{"left", []byte("a"), []byte("c")},
		{"right", []byte("c"), []byte("e")},
	} {
		_, err := as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
			Name: spec.role,
			Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: spec.key, RangeEnd: spec.end},
		})
		require.NoError(t, err)
	}

	probe := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("z")}
	before := zzvAdvEffectiveRanges(t, as, "u1", probe)
	t.Logf("effective read keys before the proposed change: %v", before)

	// The proposed permission [b,d) adds nothing: it is inside the union.
	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		{
			Type: PermissionPreviewRoleGrantPermission,
			Role: "left",
			Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("b"), RangeEnd: []byte("d")},
		},
	})
	require.NoError(t, err)
	for _, u := range result.Users {
		t.Logf("reported user=%s readAdded=%v readRevoked=%v",
			u.User, u.ReadAdded, u.ReadRevoked)
	}
	require.Empty(t, result.Users,
		"a grant fully contained in the caller's existing effective intervals changes nobody's access")
}

// TestZZVAdv529RevokingOverlappingRoleKeepsAccess is the requirement's explicit
// example: overlapping grants must not be reported as lost access.
func TestZZVAdv529RevokingOverlappingRoleKeepsAccess(t *testing.T) {
	as, root := zzvAdvStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "wide"})
	require.NoError(t, err)
	_, err = as.RoleAdd(&pb.AuthRoleAddRequest{Name: "inner"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	for _, role := range []string{"wide", "inner"} {
		_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: role})
		require.NoError(t, err)
	}
	for _, spec := range []struct {
		role string
		key  []byte
		end  []byte
	}{
		{"wide", []byte("a"), []byte("m")},
		{"inner", []byte("b"), []byte("c")},
	} {
		_, err := as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
			Name: spec.role,
			Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: spec.key, RangeEnd: spec.end},
		})
		require.NoError(t, err)
	}

	result, err := as.PreviewPermissionChanges(context.Background(), root, []*PermissionPreviewChange{
		{Type: PermissionPreviewUserRevokeRole, User: "u1", Role: "inner"},
	})
	require.NoError(t, err)
	for _, u := range result.Users {
		require.Empty(t, u.ReadRevoked,
			"revoking the contained role must not be reported as lost access")
	}
}

// TestZZVAdv529PreviewMatchesTheRealOutcome measures the preview against the real
// authorization path: whatever the preview predicts as added must really become
// readable once the same change is applied, and whatever it predicts as revoked
// must really stop being readable.
func TestZZVAdv529PreviewMatchesTheRealOutcome(t *testing.T) {
	as, root := zzvAdvStore(t)
	_, err := as.RoleAdd(&pb.AuthRoleAddRequest{Name: "r1"})
	require.NoError(t, err)
	_, err = as.UserAdd(&pb.AuthUserAddRequest{Name: "u1", Options: &authpb.UserAddOptions{NoPassword: true}})
	require.NoError(t, err)
	_, err = as.UserGrantRole(&pb.AuthUserGrantRoleRequest{User: "u1", Role: "r1"})
	require.NoError(t, err)
	_, err = as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{
		Name: "r1",
		Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("keep"), RangeEnd: []byte("keepz")},
	})
	require.NoError(t, err)

	changes := []*PermissionPreviewChange{
		{
			Type: PermissionPreviewRoleGrantPermission,
			Role: "r1",
			Perm: &authpb.Permission{PermType: authpb.Permission_READ, Key: []byte("new"), RangeEnd: []byte("newz")},
		},
	}
	result, err := as.PreviewPermissionChanges(context.Background(), root, changes)
	require.NoError(t, err)
	require.Len(t, result.Users, 1)
	added := result.Users[0].ReadAdded
	require.NotEmpty(t, added, "the preview must report the newly readable interval")

	// Apply the very same changes through the ordinary management API.
	for _, change := range changes {
		_, err := as.RoleGrantPermission(&pb.AuthRoleGrantPermissionRequest{Name: change.Role, Perm: change.Perm})
		require.NoError(t, err)
	}
	info := &AuthInfo{Username: "u1", Revision: as.Revision()}
	for _, r := range added {
		rangeEnd := r.RangeEnd
		require.NoErrorf(t, as.IsRangePermitted(info, r.Key, rangeEnd),
			"the preview promised %q..%q would become readable", r.Key, r.RangeEnd)
	}
	require.Error(t, as.IsRangePermitted(info, []byte("zzz"), nil),
		"the preview must not claim access that the real path does not grant")
}
