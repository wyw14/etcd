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

package lease

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"go.etcd.io/etcd/server/v3/storage/backend"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

// recordingDeleter records every key a revoke asks to delete.
type recordingDeleter struct {
	txn backend.BatchTx
	mu  *recorder
}

type recorder struct {
	mu   sync.Mutex
	keys []string
}

func newRecordingRangeDeleter(be backend.Backend, rec *recorder) RangeDeleter {
	return func() TxnDelete {
		// Follow the batch-tx locking contract of fakeDeleter: the batch
		// transaction is locked for the lifetime of the revoke transaction and
		// released by End.
		tx := be.BatchTx()
		tx.Lock()
		return &recordingDeleter{txn: tx, mu: rec}
	}
}

func (d *recordingDeleter) DeleteRange(key, end []byte) (int64, int64) {
	d.mu.mu.Lock()
	d.mu.keys = append(d.mu.keys, string(key))
	d.mu.mu.Unlock()
	return 0, 0
}

func (d *recordingDeleter) End() { d.txn.Unlock() }

// newProtectedRevokeLessor creates a primary lessor (leases expire normally)
// wired with a recording deleter.
func newProtectedRevokeLessor(t *testing.T, be backend.Backend, rec *recorder) *lessor {
	t.Helper()
	le := newLessor(zap.NewNop(), be, clusterLatest(), LessorConfig{MinLeaseTTL: minLeaseTTL})
	le.SetRangeDeleter(newRecordingRangeDeleter(be, rec))
	le.Promote(0)
	return le
}

func (r *recorder) sortedKeys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.keys))
	copy(out, r.keys)
	sort.Strings(out)
	return out
}

func mustPreview(t *testing.T, le Lessor, id LeaseID) *ProtectedRevokePreview {
	t.Helper()
	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("PreviewProtectedRevoke returned unexpected error: %v", err)
	}
	return p
}

// TestProtectedRevokePreviewContents verifies the preview reports the lease
// identity, the sorted current bindings and a matching credential, without
// modifying any state.
func TestProtectedRevokePreviewContents(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	le := newLessor(zap.NewNop(), be, clusterLatest(), LessorConfig{MinLeaseTTL: minLeaseTTL})
	defer le.Stop()

	l, err := le.Grant(1, 100)
	if err != nil {
		t.Fatalf("grant failed: %v", err)
	}
	items := []LeaseItem{{"foo"}, {"bar"}, {"baz"}}
	if err := le.Attach(l.ID, items); err != nil {
		t.Fatalf("attach failed: %v", err)
	}

	p := mustPreview(t, le, l.ID)
	if p.LeaseID != l.ID || p.Instance != l.instance {
		t.Fatalf("preview identity = (%d,%d), want (%d,%d)", p.LeaseID, p.Instance, l.ID, l.instance)
	}
	wantKeys := []string{"bar", "baz", "foo"}
	if !reflect.DeepEqual(p.Keys, wantKeys) {
		t.Fatalf("preview keys = %v, want %v", p.Keys, wantKeys)
	}
	if p.Token != (ProtectedRevokeToken{LeaseID: l.ID, Instance: l.instance, BindingVersion: 1}) {
		t.Fatalf("unexpected token: %+v", p.Token)
	}

	// Preview is stateless: taking it again yields the same credential.
	p2 := mustPreview(t, le, l.ID)
	if p2.Token != p.Token {
		t.Fatalf("second preview token = %+v, want %+v", p2.Token, p.Token)
	}
	// Bindings and the lease are untouched by previewing.
	if le.Lookup(l.ID) == nil {
		t.Fatalf("preview mutated lease lookup")
	}
	currentKeys := l.Keys()
	sort.Strings(currentKeys)
	if !reflect.DeepEqual(currentKeys, wantKeys) {
		t.Fatalf("preview mutated lease bindings: %v", currentKeys)
	}
}

// TestProtectedRevokePreviewNotFound ensures a missing lease is reported
// clearly when previewing.
func TestProtectedRevokePreviewNotFound(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	le := newLessor(zap.NewNop(), be, clusterLatest(), LessorConfig{MinLeaseTTL: minLeaseTTL})
	defer le.Stop()

	if _, err := le.PreviewProtectedRevoke(42); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("err = %v, want ErrLeaseNotFound", err)
	}
}

// TestProtectedRevokeSuccess is the happy path: exactly the previewed keys are
// deleted and the lease is gone.
func TestProtectedRevokeSuccess(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, err := le.Grant(1, 100)
	if err != nil {
		t.Fatalf("grant failed: %v", err)
	}
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}, {"bar"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}

	p := mustPreview(t, le, l.ID)
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("ProtectedRevoke failed: %v", err)
	}

	if got := rec.sortedKeys(); !reflect.DeepEqual(got, []string{"bar", "foo"}) {
		t.Fatalf("deleted keys = %v, want [bar foo]", got)
	}
	if le.Lookup(l.ID) != nil {
		t.Fatalf("lease still registered after protected revoke")
	}
	tx := be.BatchTx()
	tx.Lock()
	defer tx.Unlock()
	if lpb := schema.MustUnsafeGetLease(tx, int64(l.ID)); lpb != nil {
		t.Fatalf("lease still persisted: %s", lpb.String())
	}
}

// TestProtectedRevokeRejectsNewBinding ensures a key attached after the
// preview is never deleted by the protected revoke, and the lease survives.
func TestProtectedRevokeRejectsNewBinding(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, err := le.Grant(1, 100)
	if err != nil {
		t.Fatalf("grant failed: %v", err)
	}
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)

	// Business binds a new key after the preview.
	if err := le.Attach(l.ID, []LeaseItem{{"bar"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}

	err = le.ProtectedRevoke(p.Token)
	if !errors.Is(err, ErrLeaseBindingsChanged) {
		t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
	}
	if got := rec.sortedKeys(); len(got) != 0 {
		t.Fatalf("deleted %v, want no deletions when bindings changed", got)
	}
	if le.Lookup(l.ID) == nil {
		t.Fatalf("lease must survive a rejected protected revoke")
	}
	got := l.Keys()
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"bar", "foo"}) {
		t.Fatalf("keys = %v, want [bar foo]", got)
	}
}

// TestProtectedRevokeRejectsDetach ensures losing a binding invalidates the
// credential.
func TestProtectedRevokeRejectsDetach(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}, {"bar"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)

	if err := le.Detach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("detach failed: %v", err)
	}
	if err := le.ProtectedRevoke(p.Token); !errors.Is(err, ErrLeaseBindingsChanged) {
		t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
	}
	if got := rec.sortedKeys(); len(got) != 0 {
		t.Fatalf("deleted %v, want no deletions", got)
	}
}

// TestProtectedRevokeRejectsDetachAndReattach is the key requirement: even
// when the final key set is identical to the preview, a detach followed by a
// re-attach must invalidate the credential.
func TestProtectedRevokeRejectsDetachAndReattach(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	previewVersion := l.BindingVersion()
	p := mustPreview(t, le, l.ID)

	if err := le.Detach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("detach failed: %v", err)
	}
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("re-attach failed: %v", err)
	}
	if !reflect.DeepEqual(l.Keys(), p.Keys) {
		t.Fatalf("sanity check: key set = %v, want %v", l.Keys(), p.Keys)
	}
	if l.BindingVersion() == previewVersion {
		t.Fatalf("binding version must advance after detach+reattach")
	}
	if err := le.ProtectedRevoke(p.Token); !errors.Is(err, ErrLeaseBindingsChanged) {
		t.Fatalf("err = %v, want ErrLeaseBindingsChanged", err)
	}
	if got := rec.sortedKeys(); len(got) != 0 {
		t.Fatalf("deleted %v, want no deletions", got)
	}

	// A fresh preview after the churn makes the protected revoke succeed.
	p2 := mustPreview(t, le, l.ID)
	if err := le.ProtectedRevoke(p2.Token); err != nil {
		t.Fatalf("ProtectedRevoke with fresh preview failed: %v", err)
	}
	if got := rec.sortedKeys(); !reflect.DeepEqual(got, []string{"foo"}) {
		t.Fatalf("deleted = %v, want [foo]", got)
	}
}

// TestProtectedRevokeKeepsTokenOnIdempotentAttach verifies that attaching an
// already attached item (e.g. a value rewrite that the mvcc layer may report
// again) does not invalidate the credential.
func TestProtectedRevokeKeepsTokenOnIdempotentAttach(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	items := []LeaseItem{{"foo"}, {"bar"}}
	if err := le.Attach(l.ID, items); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)

	// Re-attach identical items; the binding set does not change.
	if err := le.Attach(l.ID, items); err != nil {
		t.Fatalf("re-attach failed: %v", err)
	}
	if l.BindingVersion() != p.Token.BindingVersion {
		t.Fatalf("binding version changed on idempotent attach: got %d, want %d",
			l.BindingVersion(), p.Token.BindingVersion)
	}
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("ProtectedRevoke failed: %v", err)
	}
	if got := rec.sortedKeys(); !reflect.DeepEqual(got, []string{"bar", "foo"}) {
		t.Fatalf("deleted = %v, want [bar foo]", got)
	}
}

// TestProtectedRevokeKeepsTokenOnRenew verifies ordinary keepalives do not
// invalidate the preview credential.
func TestProtectedRevokeKeepsTokenOnRenew(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)

	if _, err := le.Renew(l.ID); err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if _, err := le.Renew(l.ID); err != nil {
		t.Fatalf("second renew failed: %v", err)
	}
	if l.BindingVersion() != p.Token.BindingVersion {
		t.Fatalf("renew changed binding version")
	}
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("ProtectedRevoke after renew failed: %v", err)
	}
}

// TestProtectedRevokeInstanceMismatchOnRegrant verifies a credential cannot be
// replayed against a new lease granted with a revoked lease's ID.
func TestProtectedRevokeInstanceMismatchOnRegrant(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l1, _ := le.Grant(7, 100)
	if err := le.Attach(l1.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l1.ID)

	if err := le.Revoke(l1.ID); err != nil {
		t.Fatalf("plain revoke failed: %v", err)
	}
	// Same ID is granted again: a different lease instance.
	l2, err := le.Grant(7, 100)
	if err != nil {
		t.Fatalf("re-grant failed: %v", err)
	}
	if l2.instance == l1.instance {
		t.Fatalf("re-granted lease reused instance identity %d", l2.instance)
	}

	if err := le.ProtectedRevoke(p.Token); !errors.Is(err, ErrLeaseInstanceMismatch) {
		t.Fatalf("err = %v, want ErrLeaseInstanceMismatch", err)
	}
	// The new instance is untouched.
	if le.Lookup(l2.ID) == nil {
		t.Fatalf("re-granted lease must not be revoked by an old credential")
	}
	// The old credential must not have deleted anything by itself; only the
	// earlier plain revoke of the old instance deleted "foo".
	if got := rec.sortedKeys(); !reflect.DeepEqual(got, []string{"foo"}) {
		t.Fatalf("old credential deleted keys: %v", got)
	}
	if le.Lookup(l2.ID).BindingVersion() != 0 {
		t.Fatalf("new lease instance bindings were altered: version %d", le.Lookup(l2.ID).BindingVersion())
	}
}

// TestProtectedRevokeDuplicateRevoke ensures repeating a protected revoke has
// a definite "not found" outcome instead of panicking.
func TestProtectedRevokeDuplicateRevoke(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)

	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("first protected revoke failed: %v", err)
	}
	if err := le.ProtectedRevoke(p.Token); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("duplicate revoke err = %v, want ErrLeaseNotFound", err)
	}
}

// TestProtectedRevokeMalformedToken covers impossible credentials.
func TestProtectedRevokeMalformedToken(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	le := newProtectedRevokeLessor(t, be, &recorder{})
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	for _, bad := range []ProtectedRevokeToken{
		{LeaseID: NoLease, Instance: 1, BindingVersion: 0},
		{LeaseID: l.ID, Instance: 0, BindingVersion: 0},
	} {
		if err := le.ProtectedRevoke(bad); !errors.Is(err, ErrProtectedRevokeTokenInvalid) {
			t.Fatalf("token %+v: err = %v, want ErrProtectedRevokeTokenInvalid", bad, err)
		}
	}
	if le.Lookup(l.ID) == nil {
		t.Fatalf("malformed token must not revoke anything")
	}
}

// TestProtectedRevokeDoesNotRestoreExpiredLease ensures an expired lease can be
// revoked with a definite result and is never renewed/restored by the flow.
func TestProtectedRevokeDoesNotRestoreExpiredLease(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)

	// Simulate the lease expiring before the protected revoke is applied.
	l.expiryMu.Lock()
	l.expiry = time.Now().Add(-time.Second)
	l.expiryMu.Unlock()

	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("ProtectedRevoke of expired lease failed: %v", err)
	}
	if got := rec.sortedKeys(); !reflect.DeepEqual(got, []string{"foo"}) {
		t.Fatalf("deleted = %v, want [foo]", got)
	}
	// A renew racing the revoke must observe the closed revokec and fail; the
	// expired lease must not come back.
	if _, err := le.Renew(l.ID); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("renew after revoke err = %v, want ErrLeaseNotFound", err)
	}
	if le.Lookup(l.ID) != nil {
		t.Fatalf("revoked expired lease must stay gone")
	}
}

// TestProtectedRevokeAcrossDemotion verifies leadership changes do not corrupt
// the decision: unchanged bindings still produce a successful revoke.
func TestProtectedRevokeAcrossDemotion(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	rec := &recorder{}
	le := newProtectedRevokeLessor(t, be, rec)
	defer le.Stop()

	l, _ := le.Grant(1, 100)
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)

	// Leadership is lost (expiries become "forever") and regained. The binding
	// set is untouched, so the credential stays valid.
	le.Demote()
	le.Promote(0)

	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("ProtectedRevoke across demotion failed: %v", err)
	}
	if got := rec.sortedKeys(); !reflect.DeepEqual(got, []string{"foo"}) {
		t.Fatalf("deleted = %v, want [foo]", got)
	}
}

// TestProtectedRevokeRecoveryRejectsStaleState ensures a credential based on
// pre-recovery state cannot revoke a recovered lease unless the instance and
// binding set still match exactly; recovered bindings are rebuilt from the
// replicated backend, so here the old credential is rejected with a definite
// error and the lease survives until a fresh preview confirms it.
func TestProtectedRevokeRecoveryRejectsStaleState(t *testing.T) {
	dir, be := NewTestBackend(t)
	defer os.RemoveAll(dir)
	defer be.Close()

	le := newLessor(zap.NewNop(), be, clusterLatest(), LessorConfig{MinLeaseTTL: minLeaseTTL})
	l, _ := le.Grant(5, 100)
	if err := le.Attach(l.ID, []LeaseItem{{"foo"}}); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	p := mustPreview(t, le, l.ID)
	le.Stop()

	// Simulate process restart: a new lessor recovers persisted leases. The
	// binding set is rebuilt later by the mvcc layer and starts empty, so the
	// old credential (version 1) cannot match.
	rec := &recorder{}
	le2 := newLessor(zap.NewNop(), be, clusterLatest(), LessorConfig{MinLeaseTTL: minLeaseTTL})
	defer le2.Stop()
	le2.SetRangeDeleter(newRecordingRangeDeleter(be, rec))

	recovered := le2.Lookup(l.ID)
	if recovered == nil {
		t.Fatalf("lease %d should be recovered from backend", l.ID)
	}
	if err := le2.ProtectedRevoke(p.Token); !errors.Is(err, ErrLeaseBindingsChanged) {
		t.Fatalf("stale token after recovery: err = %v, want ErrLeaseBindingsChanged", err)
	}
	if got := rec.sortedKeys(); len(got) != 0 {
		t.Fatalf("stale token deleted keys: %v", got)
	}

	// A fresh preview against recovered state works and revokes the lease.
	p2 := mustPreview(t, le2, l.ID)
	if len(p2.Keys) != 0 || p2.Token.BindingVersion != 0 {
		t.Fatalf("recovered preview = %+v, want no keys and version 0", p2)
	}
	if err := le2.ProtectedRevoke(p2.Token); err != nil {
		t.Fatalf("ProtectedRevoke after re-preview failed: %v", err)
	}
	if le2.Lookup(l.ID) != nil {
		t.Fatalf("lease still registered after protected revoke")
	}
}

// TestProtectedRevokeConcurrentBindings is the atomicity guarantee: when a
// binding change races the revoke, either the revoke wins (and every racing
// attach fails because the lease is already gone) or the credential is
// rejected (and nothing is deleted); a key not covered by the preview is never
// deleted.
func TestProtectedRevokeConcurrentBindings(t *testing.T) {
	const iterations = 50
	const racers = 8

	for iter := 0; iter < iterations; iter++ {
		dir, be := NewTestBackend(t)
		rec := &recorder{}
		le := newProtectedRevokeLessor(t, be, rec)

		l, _ := le.Grant(LeaseID(1000+iter), 100)
		if err := le.Attach(l.ID, []LeaseItem{{"previewed"}}); err != nil {
			t.Fatalf("attach failed: %v", err)
		}
		p := mustPreview(t, le, l.ID)

		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, racers)
		wg.Add(racers)
		for i := 0; i < racers; i++ {
			i := i
			go func() {
				defer wg.Done()
				<-start
				errs[i] = le.Attach(l.ID, []LeaseItem{{Key: fmt.Sprintf("new-%d", i)}})
			}()
		}
		close(start)

		revokeErr := le.ProtectedRevoke(p.Token)
		wg.Wait()

		switch {
		case revokeErr == nil:
			// Revoke won the race: only the previewed key may be deleted, and
			// every concurrent attach must have lost the lease.
			if got := rec.sortedKeys(); !reflect.DeepEqual(got, []string{"previewed"}) {
				t.Fatalf("iter %d: deleted = %v, want [previewed]", iter, got)
			}
			for i, err := range errs {
				if !errors.Is(err, ErrLeaseNotFound) {
					t.Fatalf("iter %d: racer %d attached to a revoking lease: %v", iter, i, err)
				}
			}
		case errors.Is(revokeErr, ErrLeaseBindingsChanged):
			// A binding was inserted before the decision: nothing is deleted
			// and the lease (with all bindings) survives.
			if got := rec.sortedKeys(); len(got) != 0 {
				t.Fatalf("iter %d: deleted %v after rejecting credential", iter, got)
			}
			if le.Lookup(l.ID) == nil {
				t.Fatalf("iter %d: lease lost on rejected protected revoke", iter)
			}
		default:
			t.Fatalf("iter %d: unexpected revoke error: %v", iter, revokeErr)
		}

		le.Stop()
		be.Close()
		os.RemoveAll(dir)
	}
}
