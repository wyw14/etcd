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

// Independent acceptance verification for precheck 530.
//
// Everything here runs against the real mvcc store on a real backend: keys are
// written through mvcc (so Attach/Detach happen exactly as in production) and
// the protected revoke is checked through the exported Lessor API only.

package lease_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"go.etcd.io/etcd/pkg/v3/traceutil"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	"go.etcd.io/etcd/server/v3/lease"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/mvcc"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

// ---------------------------------------------------------------------------
// fixture: a real lessor wired to a real mvcc store
// ---------------------------------------------------------------------------

type zzv530Env struct {
	le lease.Lessor
	kv mvcc.KV
}

func zzv530NewEnv(t *testing.T) *zzv530Env {
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
	return &zzv530Env{le: le, kv: kv}
}

// zzv530Grant grants a lease and returns its ID.
func (e *zzv530Env) zzv530Grant(t *testing.T, id lease.LeaseID, ttl int64) {
	t.Helper()
	_, err := e.le.Grant(id, ttl)
	if err != nil {
		t.Fatalf("grant %d: %v", id, err)
	}
}

// zzv530Put writes a key through the real mvcc store, which attaches it to the
// lease exactly as a client Put would.
func (e *zzv530Env) zzv530Put(t *testing.T, key, value string, lid lease.LeaseID) {
	t.Helper()
	txn := e.kv.Write(traceutil.TODO())
	txn.Put([]byte(key), []byte(value), lid)
	txn.End()
}

// zzv530Delete removes a key through mvcc, detaching it from its lease.
func (e *zzv530Env) zzv530Delete(t *testing.T, key string) {
	t.Helper()
	txn := e.kv.Write(traceutil.TODO())
	txn.DeleteRange([]byte(key), nil)
	txn.End()
}

// zzv530Value reads a key through the real read path.
func (e *zzv530Env) zzv530Value(t *testing.T, key string) (string, bool) {
	t.Helper()
	txn := e.kv.Read(mvcc.ConcurrentReadTxMode, traceutil.TODO())
	defer txn.End()
	res, err := txn.Range(context.Background(), []byte(key), nil, mvcc.RangeOptions{})
	if err != nil {
		t.Fatalf("range %q: %v", key, err)
	}
	if len(res.KVs) == 0 {
		return "", false
	}
	return string(res.KVs[0].Value), true
}

func zzv530RequireKeys(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys = %v, want %v", got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// TestZZV530PreviewThenRevoke is the happy path: the preview reports the lease
// identity and the sorted bound keys, and the revoke removes exactly those keys
// from the real store.
func TestZZV530PreviewThenRevoke(t *testing.T) {
	e := zzv530NewEnv(t)
	const lid = lease.LeaseID(1)
	e.zzv530Grant(t, lid, 600)

	e.zzv530Put(t, "bravo", "b", lid)
	e.zzv530Put(t, "alpha", "a", lid)
	e.zzv530Put(t, "charlie", "c", lid)
	e.zzv530Put(t, "unbound", "u", lease.NoLease)

	preview, err := e.le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	zzv530RequireKeys(t, preview.Keys, "alpha", "bravo", "charlie")
	if preview.LeaseID != lid {
		t.Errorf("preview lease id = %d, want %d", preview.LeaseID, lid)
	}
	if preview.Token.LeaseID != lid {
		t.Errorf("token lease id = %d, want %d", preview.Token.LeaseID, lid)
	}
	if preview.Token.Instance == 0 {
		t.Errorf("token must carry a lease instance identity")
	}
	if preview.Token.Instance != preview.Instance {
		t.Errorf("token instance %d does not match the preview instance %d",
			preview.Token.Instance, preview.Instance)
	}

	// Taking a preview must not change anything.
	for _, key := range []string{"alpha", "bravo", "charlie", "unbound"} {
		if _, ok := e.zzv530Value(t, key); !ok {
			t.Fatalf("key %q disappeared after taking a preview", key)
		}
	}
	if e.le.Lookup(lid) == nil {
		t.Fatal("the lease disappeared after taking a preview")
	}

	if err := e.le.ProtectedRevoke(preview.Token); err != nil {
		t.Fatalf("protected revoke: %v", err)
	}

	for _, key := range []string{"alpha", "bravo", "charlie"} {
		if _, ok := e.zzv530Value(t, key); ok {
			t.Errorf("previewed key %q must be deleted", key)
		}
	}
	if _, ok := e.zzv530Value(t, "unbound"); !ok {
		t.Error("a key without a lease must not be deleted")
	}
	if e.le.Lookup(lid) != nil {
		t.Error("the lease must be gone after a successful protected revoke")
	}
}


// TestZZV530UnknownLeaseAndMalformedToken covers the definite failure results.
func TestZZV530UnknownLeaseAndMalformedToken(t *testing.T) {
	e := zzv530NewEnv(t)

	t.Run("preview of a missing lease", func(t *testing.T) {
		if _, err := e.le.PreviewProtectedRevoke(lease.LeaseID(42)); !errors.Is(err, lease.ErrLeaseNotFound) {
			t.Fatalf("err = %v, want ErrLeaseNotFound", err)
		}
	})

	t.Run("revoke of a missing lease", func(t *testing.T) {
		err := e.le.ProtectedRevoke(lease.ProtectedRevokeToken{LeaseID: lease.LeaseID(42), Instance: 1})
		if !errors.Is(err, lease.ErrLeaseNotFound) {
			t.Fatalf("err = %v, want ErrLeaseNotFound", err)
		}
	})

	t.Run("malformed tokens", func(t *testing.T) {
		cases := map[string]lease.ProtectedRevokeToken{
			"no lease":     {LeaseID: lease.NoLease, Instance: 1},
			"no instance":  {LeaseID: lease.LeaseID(7), Instance: 0},
			"missing both": {},
		}
		for name, token := range cases {
			if err := e.le.ProtectedRevoke(token); !errors.Is(err, lease.ErrProtectedRevokeTokenInvalid) {
				t.Errorf("%s: err = %v, want ErrProtectedRevokeTokenInvalid", name, err)
			}
		}
	})
}

// TestZZV530SameIDRegrantInvalidatesToken proves a credential cannot be replayed
// against a new lease that reuses the id.
func TestZZV530SameIDRegrantInvalidatesToken(t *testing.T) {
	e := zzv530NewEnv(t)
	const lid = lease.LeaseID(9)
	e.zzv530Grant(t, lid, 600)
	e.zzv530Put(t, "original", "v", lid)

	preview, err := e.le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if err := e.le.Revoke(lid); err != nil {
		t.Fatalf("plain revoke: %v", err)
	}

	// Grant the same id again and bind a new key to it.
	e.zzv530Grant(t, lid, 600)
	e.zzv530Put(t, "replacement", "v2", lid)

	if err := e.le.ProtectedRevoke(preview.Token); !errors.Is(err, lease.ErrLeaseInstanceMismatch) {
		t.Fatalf("err = %v, want ErrLeaseInstanceMismatch", err)
	}
	if _, ok := e.zzv530Value(t, "replacement"); !ok {
		t.Error("a stale credential must not delete the new lease's keys")
	}
	if e.le.Lookup(lid) == nil {
		t.Error("the new lease must survive a rejected protected revoke")
	}

	// The fresh credential for the new instance works.
	fresh, err := e.le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview of the new instance: %v", err)
	}
	if fresh.Token.Instance == preview.Token.Instance {
		t.Error("a re-granted lease must get a new instance identity")
	}
	if err := e.le.ProtectedRevoke(fresh.Token); err != nil {
		t.Fatalf("protected revoke with the fresh credential: %v", err)
	}
	if _, ok := e.zzv530Value(t, "replacement"); ok {
		t.Error("the fresh credential must delete the new lease's keys")
	}
}

// TestZZV530BindingChangesInvalidateToken covers the attach, detach and
// detach-then-reattach cases plus the cases that must keep the credential.
func TestZZV530BindingChangesInvalidateToken(t *testing.T) {
	t.Run("a key bound after the preview invalidates it", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(1)
		e.zzv530Grant(t, lid, 600)
		e.zzv530Put(t, "first", "v", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		e.zzv530Put(t, "second", "v", lid)

		if err := e.le.ProtectedRevoke(preview.Token); !errors.Is(err, lease.ErrLeaseBindingsChanged) {
			t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
		}
		for _, key := range []string{"first", "second"} {
			if _, ok := e.zzv530Value(t, key); !ok {
				t.Errorf("a rejected revoke must delete nothing, but %q is gone", key)
			}
		}
		if e.le.Lookup(lid) == nil {
			t.Error("the lease must survive a rejected protected revoke")
		}
	})

	t.Run("a key detached after the preview invalidates it", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(2)
		e.zzv530Grant(t, lid, 600)
		e.zzv530Put(t, "keep", "v", lid)
		e.zzv530Put(t, "drop", "v", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		e.zzv530Delete(t, "drop")

		if err := e.le.ProtectedRevoke(preview.Token); !errors.Is(err, lease.ErrLeaseBindingsChanged) {
			t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
		}
		if _, ok := e.zzv530Value(t, "keep"); !ok {
			t.Error("a rejected revoke must not delete the remaining key")
		}
	})

	t.Run("detach followed by reattach invalidates it even though the key set matches", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(3)
		e.zzv530Grant(t, lid, 600)
		e.zzv530Put(t, "cycle", "v1", lid)
		e.zzv530Put(t, "stable", "v", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		zzv530RequireKeys(t, preview.Keys, "cycle", "stable")

		// Remove the key and bind it again with the same value and the same
		// lease, so the final key set is identical to the previewed one.
		e.zzv530Delete(t, "cycle")
		e.zzv530Put(t, "cycle", "v1", lid)

		after, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("second preview: %v", err)
		}
		zzv530RequireKeys(t, after.Keys, "cycle", "stable")

		if err := e.le.ProtectedRevoke(preview.Token); !errors.Is(err, lease.ErrLeaseBindingsChanged) {
			t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
		}
		for _, key := range []string{"cycle", "stable"} {
			if _, ok := e.zzv530Value(t, key); !ok {
				t.Errorf("a rejected revoke must delete nothing, but %q is gone", key)
			}
		}

		// The credential taken after the round trip is accepted.
		if err := e.le.ProtectedRevoke(after.Token); err != nil {
			t.Fatalf("protected revoke with the current credential: %v", err)
		}
		for _, key := range []string{"cycle", "stable"} {
			if _, ok := e.zzv530Value(t, key); ok {
				t.Errorf("key %q must be deleted by the accepted credential", key)
			}
		}
	})

	t.Run("rewriting a bound key's value keeps the credential", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(4)
		e.zzv530Grant(t, lid, 600)
		e.zzv530Put(t, "k", "v1", lid)
		e.zzv530Put(t, "other", "o", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		e.zzv530Put(t, "k", "v2", lid)

		if err := e.le.ProtectedRevoke(preview.Token); err != nil {
			t.Fatalf("rewriting a bound value must not invalidate the credential: %v", err)
		}
		for _, key := range []string{"k", "other"} {
			if _, ok := e.zzv530Value(t, key); ok {
				t.Errorf("key %q must be deleted", key)
			}
		}
	})

	t.Run("renewing the lease keeps the credential", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(5)
		e.zzv530Grant(t, lid, 600)
		e.zzv530Put(t, "k", "v", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		for i := 0; i < 3; i++ {
			if _, err := e.le.Renew(lid); err != nil {
				t.Fatalf("renew %d: %v", i, err)
			}
		}
		if err := e.le.ProtectedRevoke(preview.Token); err != nil {
			t.Fatalf("renewal must not invalidate the credential: %v", err)
		}
		if _, ok := e.zzv530Value(t, "k"); ok {
			t.Error("the key must be deleted")
		}
	})
}

// TestZZV530RevokeIsAtomicAgainstConcurrentAttach inserts an Attach attempt
// while the revoke is deleting keys and proves the new binding survives.
func TestZZV530RevokeIsAtomicAgainstConcurrentAttach(t *testing.T) {
	e := zzv530NewEnv(t)
	const lid = lease.LeaseID(1)
	e.zzv530Grant(t, lid, 600)
	e.zzv530Put(t, "covered", "v", lid)
	e.zzv530Put(t, "also", "v", lid)

	preview, err := e.le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	zzv530RequireKeys(t, preview.Keys, "also", "covered")

	var attachErr error
	// Race an Attach against the revoke: whichever order the scheduler picks,
	// the credential must either delete exactly the previewed keys or fail
	// without deleting anything.
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		attachErr = e.le.Attach(lid, []lease.LeaseItem{{Key: "late"}})
	}()
	close(start)

	revokeErr := e.le.ProtectedRevoke(preview.Token)
	wg.Wait()

	if revokeErr == nil {
		if attachErr == nil {
			t.Fatal("a binding was accepted while the revoke reported success")
		}
		if !errors.Is(attachErr, lease.ErrLeaseNotFound) {
			t.Fatalf("attach err = %v, want ErrLeaseNotFound while frozen", attachErr)
		}
		for _, key := range []string{"covered", "also"} {
			if _, ok := e.zzv530Value(t, key); ok {
				t.Errorf("previewed key %q must be deleted", key)
			}
		}
		if _, ok := e.zzv530Value(t, "late"); ok {
			t.Error("a key bound after the preview must never be deleted")
		}
		return
	}

	// The revoke was rejected: nothing may have been deleted.
	if !errors.Is(revokeErr, lease.ErrLeaseBindingsChanged) && !errors.Is(revokeErr, lease.ErrLeaseNotFound) {
		t.Fatalf("unexpected revoke error: %v", revokeErr)
	}
	for _, key := range []string{"covered", "also"} {
		if _, ok := e.zzv530Value(t, key); !ok {
			t.Errorf("a rejected revoke must delete nothing, but %q is gone", key)
		}
	}
}

// TestZZV530DeletionIsAClosedDecisionForcesTheFreeze drives the deletion phase
// directly: while the revoke is deleting, a concurrent Attach must be refused,
// so no binding can slip in between the credential check and the deletion.
func TestZZV530DeletionIsAClosedDecisionForcesTheFreeze(t *testing.T) {
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

	const lid = lease.LeaseID(1)
	if _, err := le.Grant(lid, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	put := func(key, value string) {
		t.Helper()
		txn := kv.Write(traceutil.TODO())
		txn.Put([]byte(key), []byte(value), lid)
		txn.End()
	}
	put("covered", "v")

	preview, err := le.PreviewProtectedRevoke(lid)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	var (
		hookErr   error
		hookRan   bool
		hookMutex sync.Mutex
	)
	// The hook runs inside the deletion phase of the revoke.
	le.SetRangeDeleter(newZZV530HookedDeleter(kv, func() {
		hookMutex.Lock()
		defer hookMutex.Unlock()
		hookRan = true
		hookErr = le.Attach(lid, []lease.LeaseItem{{Key: "late"}})
	}))

	if err := le.ProtectedRevoke(preview.Token); err != nil {
		t.Fatalf("protected revoke: %v", err)
	}

	hookMutex.Lock()
	defer hookMutex.Unlock()
	if !hookRan {
		t.Fatal("the deletion hook never ran, so the window was not exercised")
	}
	if hookErr == nil {
		t.Fatal("a binding was accepted while the previewed keys were being deleted")
	}
	if !errors.Is(hookErr, lease.ErrLeaseNotFound) {
		t.Fatalf("attach during deletion = %v, want ErrLeaseNotFound", hookErr)
	}

	txn := kv.Read(mvcc.ConcurrentReadTxMode, traceutil.TODO())
	defer txn.End()
	res, err := txn.Range(context.Background(), []byte("late"), nil, mvcc.RangeOptions{})
	if err != nil {
		t.Fatalf("range late: %v", err)
	}
	if len(res.KVs) != 0 {
		t.Fatalf("the rejected binding must not be visible, got %d kv", len(res.KVs))
	}
}

// newZZV530HookedDeleter returns a RangeDeleter that delegates to the store's
// real delete transaction and runs hook once at the start of the deletion.
func newZZV530HookedDeleter(kv mvcc.KV, hook func()) lease.RangeDeleter {
	var once sync.Once
	return func() lease.TxnDelete {
		txn := kv.Write(traceutil.TODO())
		return &zzv530HookedTxnDelete{inner: txn, once: &once, hook: hook}
	}
}

type zzv530HookedTxnDelete struct {
	inner mvcc.TxnWrite
	once  *sync.Once
	hook  func()
}

func (d *zzv530HookedTxnDelete) DeleteRange(key, end []byte) (int64, int64) {
	d.once.Do(d.hook)
	return d.inner.DeleteRange(key, end)
}

func (d *zzv530HookedTxnDelete) End() { d.inner.End() }

// TestZZV530DefiniteResultsForExpiryAndDuplicates covers the remaining
// lifecycle results.
func TestZZV530DefiniteResultsForExpiryAndDuplicates(t *testing.T) {
	t.Run("duplicate revoke is not found", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(1)
		e.zzv530Grant(t, lid, 600)
		e.zzv530Put(t, "k", "v", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if err := e.le.ProtectedRevoke(preview.Token); err != nil {
			t.Fatalf("first revoke: %v", err)
		}
		if err := e.le.ProtectedRevoke(preview.Token); !errors.Is(err, lease.ErrLeaseNotFound) {
			t.Fatalf("second revoke = %v, want ErrLeaseNotFound", err)
		}
		if err := e.le.Revoke(lid); !errors.Is(err, lease.ErrLeaseNotFound) {
			t.Fatalf("plain revoke after protected revoke = %v, want ErrLeaseNotFound", err)
		}
	})

	t.Run("an expired lease cannot be protected revived", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(2)
		e.zzv530Grant(t, lid, 5)
		e.zzv530Put(t, "expiring", "v", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}

		// Wait for the lease to expire, then let the lessor revoke it through
		// the normal expiry path.
		deadline := time.Now().Add(30 * time.Second)
		for e.le.Lookup(lid) != nil && time.Now().Before(deadline) {
			select {
			case expired := <-e.le.ExpiredLeasesC():
				for _, l := range expired {
					if err := e.le.Revoke(l.ID); err != nil && !errors.Is(err, lease.ErrLeaseNotFound) {
						t.Fatalf("expiry revoke: %v", err)
					}
				}
			case <-time.After(200 * time.Millisecond):
			}
		}
		if e.le.Lookup(lid) != nil {
			t.Fatalf("lease %d never expired", lid)
		}

		if err := e.le.ProtectedRevoke(preview.Token); !errors.Is(err, lease.ErrLeaseNotFound) {
			t.Fatalf("protected revoke of an expired lease = %v, want ErrLeaseNotFound", err)
		}
		if _, err := e.le.Renew(lid); !errors.Is(err, lease.ErrLeaseNotFound) {
			t.Fatalf("renew of an expired lease = %v, want ErrLeaseNotFound", err)
		}
		if e.le.Lookup(lid) != nil {
			t.Error("an expired lease must not be restored")
		}
	})

	t.Run("demote and promote do not change the decision", func(t *testing.T) {
		e := zzv530NewEnv(t)
		const lid = lease.LeaseID(3)
		e.zzv530Grant(t, lid, 600)
		e.zzv530Put(t, "k", "v", lid)

		preview, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		e.le.Demote()
		afterDemote, err := e.le.PreviewProtectedRevoke(lid)
		if err != nil {
			t.Fatalf("preview while demoted: %v", err)
		}
		if afterDemote.Token.Instance != preview.Token.Instance {
			t.Errorf("demote changed the instance: %d -> %d",
				preview.Token.Instance, afterDemote.Token.Instance)
		}
		if afterDemote.Token != preview.Token {
			t.Errorf("demote changed the credential: %+v -> %+v", preview.Token, afterDemote.Token)
		}
		e.le.Promote(0)

		// The credential taken before the demotion is still accepted.
		if err := e.le.ProtectedRevoke(preview.Token); err != nil {
			t.Fatalf("protected revoke after demote/promote: %v", err)
		}
		if _, ok := e.zzv530Value(t, "k"); ok {
			t.Error("the key must be deleted")
		}
	})
}

// TestZZV530ExistingLeaseBehaviourUnchanged is the compatibility check.
func TestZZV530ExistingLeaseBehaviourUnchanged(t *testing.T) {
	e := zzv530NewEnv(t)
	const lid = lease.LeaseID(1)
	e.zzv530Grant(t, lid, 600)

	t.Run("granting an existing id fails", func(t *testing.T) {
		if _, err := e.le.Grant(lid, 600); !errors.Is(err, lease.ErrLeaseExists) {
			t.Fatalf("err = %v, want ErrLeaseExists", err)
		}
	})

	t.Run("plain attach, lookup and revoke still work", func(t *testing.T) {
		if err := e.le.Attach(lid, []lease.LeaseItem{{Key: "plain"}}); err != nil {
			t.Fatalf("attach: %v", err)
		}
		if got := e.le.GetLease(lease.LeaseItem{Key: "plain"}); got != lid {
			t.Fatalf("GetLease = %d, want %d", got, lid)
		}
		if err := e.le.Detach(lid, []lease.LeaseItem{{Key: "plain"}}); err != nil {
			t.Fatalf("detach: %v", err)
		}
		if got := e.le.GetLease(lease.LeaseItem{Key: "plain"}); got != lease.NoLease {
			t.Fatalf("GetLease after detach = %d, want NoLease", got)
		}
		if _, err := e.le.Renew(lid); err != nil {
			t.Fatalf("renew: %v", err)
		}
	})

	t.Run("plain revoke deletes the bound keys", func(t *testing.T) {
		e.zzv530Put(t, "x", "v", lid)
		e.zzv530Put(t, "y", "v", lid)
		if err := e.le.Revoke(lid); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		for _, key := range []string{"x", "y"} {
			if _, ok := e.zzv530Value(t, key); ok {
				t.Errorf("plain revoke must delete %q", key)
			}
		}
	})

	t.Run("lease ids remain independent", func(t *testing.T) {
		other := lease.LeaseID(2)
		e.zzv530Grant(t, other, 600)
		e.zzv530Put(t, "mine", "v", other)

		preview, err := e.le.PreviewProtectedRevoke(other)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if err := e.le.ProtectedRevoke(preview.Token); err != nil {
			t.Fatalf("protected revoke: %v", err)
		}
		if _, ok := e.zzv530Value(t, "mine"); ok {
			t.Error("the other lease's key must be deleted")
		}
	})
}

