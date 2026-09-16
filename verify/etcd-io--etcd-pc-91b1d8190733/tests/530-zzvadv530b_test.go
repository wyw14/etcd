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

// Adversarial checks for the leader-switch scenario of precheck 530.

package lease_test

import (
	"errors"
	"testing"

	"go.uber.org/zap/zaptest"

	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	"go.etcd.io/etcd/server/v3/lease"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

func TestZZVAdv530LeaderSwitchIsDefinite(t *testing.T) {
	lg := zaptest.NewLogger(t)
	be, _ := betesting.NewDefaultTmpBackend(t)
	t.Cleanup(func() { betesting.Close(t, be) })
	cluster := membership.NewCluster(lg)
	cluster.SetBackend(schema.NewMembershipBackend(lg, be))
	le := lease.NewLessor(lg, be, cluster, lease.LessorConfig{MinLeaseTTL: 5})
	t.Cleanup(le.Stop)
	le.Promote(0)

	const id = lease.LeaseID(1)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	// The member loses leadership between preview and revoke.
	le.Demote()
	if err := le.ProtectedRevoke(p.Token); err != nil && !errors.Is(err, lease.ErrLeaseNotFound) {
		t.Fatalf("demoted lessor returned %v, want a documented result", err)
	}

	// And after regaining leadership the credential must still be decidable.
	if _, err := le.Grant(lease.LeaseID(2), 600); err != nil {
		t.Fatalf("grant after promote: %v", err)
	}
	le.Promote(0)
	if _, err := le.PreviewProtectedRevoke(lease.LeaseID(2)); err != nil {
		t.Fatalf("preview after promote: %v", err)
	}
}
