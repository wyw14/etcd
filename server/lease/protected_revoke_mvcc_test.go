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

package lease_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zaptest"

	"go.etcd.io/etcd/pkg/v3/traceutil"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	"go.etcd.io/etcd/server/v3/lease"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/mvcc"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

func newProtectedRevokeMVCCEnv(t *testing.T) (lease.Lessor, mvcc.KV) {
	t.Helper()
	lg := zaptest.NewLogger(t)
	be, _ := betesting.NewDefaultTmpBackend(t)
	t.Cleanup(func() { betesting.Close(t, be) })

	cluster := membership.NewCluster(lg)
	cluster.SetBackend(schema.NewMembershipBackend(lg, be))
	le := lease.NewLessor(lg, be, cluster, lease.LessorConfig{MinLeaseTTL: 5})
	t.Cleanup(le.Stop)
	kv := mvcc.NewStore(lg, be, le, mvcc.StoreConfig{})
	t.Cleanup(func() {
		if err := kv.Close(); err != nil {
			t.Errorf("kv close failed: %v", err)
		}
	})
	le.Promote(0)
	return le, kv
}

// TestProtectedRevokeMVCCValueRewrite exercises the flow against the real mvcc
// store: rewriting the value of an already bound key must not invalidate the
// credential.
func TestProtectedRevokeMVCCValueRewrite(t *testing.T) {
	le, kv := newProtectedRevokeMVCCEnv(t)

	lid := lease.LeaseID(1)
	if _, err := le.Grant(lid, 100); err != nil {
		t.Fatalf("grant failed: %v", err)
	}
	put := func(key, value string) {
		t.Helper()
		tw := kv.Write(traceutil.TODO())
		tw.Put([]byte(key), []byte(value), lid)
		tw.End()
	}
	put("foo", "v1")

	p, err := le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}

	// Rewriting only the value of the already bound key is not a binding change.
	put("foo", "v2")
	if le.Lookup(lid).BindingVersion() != p.Token.BindingVersion {
		t.Fatalf("value rewrite changed binding version")
	}
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("ProtectedRevoke failed: %v", err)
	}
	r, err := kv.Range(context.Background(), []byte("foo"), nil, mvcc.RangeOptions{})
	if err != nil {
		t.Fatalf("range failed: %v", err)
	}
	if len(r.KVs) != 0 {
		t.Fatalf("previewed key still present after protected revoke: %s", r.KVs[0].Value)
	}
	if le.Lookup(lid) != nil {
		t.Fatalf("lease should be revoked")
	}
}

// TestProtectedRevokeMVCCNewBinding proves a newly bound key is not deleted by
// a protected revoke whose credential predates the binding.
func TestProtectedRevokeMVCCNewBinding(t *testing.T) {
	le, kv := newProtectedRevokeMVCCEnv(t)

	lid := lease.LeaseID(1)
	if _, err := le.Grant(lid, 100); err != nil {
		t.Fatalf("grant failed: %v", err)
	}
	put := func(key, value string) {
		t.Helper()
		tw := kv.Write(traceutil.TODO())
		tw.Put([]byte(key), []byte(value), lid)
		tw.End()
	}
	put("foo", "v1")

	p, err := le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}

	// A new key is bound to the lease after the preview.
	put("bar", "v1")
	if err := le.ProtectedRevoke(p.Token); !errors.Is(err, lease.ErrLeaseBindingsChanged) {
		t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
	}

	// Neither key is deleted and the lease survives.
	for _, key := range []string{"foo", "bar"} {
		r, err := kv.Range(context.Background(), []byte(key), nil, mvcc.RangeOptions{})
		if err != nil {
			t.Fatalf("range %s failed: %v", key, err)
		}
		if len(r.KVs) != 1 {
			t.Fatalf("key %q count = %d, want 1", key, len(r.KVs))
		}
	}
	if le.Lookup(lid) == nil {
		t.Fatalf("lease must survive rejected protected revoke")
	}
}

// TestProtectedRevokeMVCCDeleteBinding verifies that deleting a bound key
// (detach) invalidates the credential and protects the remaining bindings.
func TestProtectedRevokeMVCCDeleteBinding(t *testing.T) {
	le, kv := newProtectedRevokeMVCCEnv(t)

	lid := lease.LeaseID(1)
	if _, err := le.Grant(lid, 100); err != nil {
		t.Fatalf("grant failed: %v", err)
	}
	put := func(key, value string) {
		t.Helper()
		tw := kv.Write(traceutil.TODO())
		tw.Put([]byte(key), []byte(value), lid)
		tw.End()
	}
	put("foo", "v1")
	put("bar", "v1")

	p, err := le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}

	tw := kv.Write(traceutil.TODO())
	if n, _ := tw.DeleteRange([]byte("foo"), nil); n != 1 {
		t.Fatalf("deleted %d keys, want 1", n)
	}
	tw.End()

	if err := le.ProtectedRevoke(p.Token); !errors.Is(err, lease.ErrLeaseBindingsChanged) {
		t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
	}
	r, err := kv.Range(context.Background(), []byte("bar"), nil, mvcc.RangeOptions{})
	if err != nil {
		t.Fatalf("range failed: %v", err)
	}
	if len(r.KVs) != 1 {
		t.Fatalf("bar count = %d, want 1", len(r.KVs))
	}
	if le.Lookup(lid) == nil {
		t.Fatalf("lease must survive rejected protected revoke")
	}
}
