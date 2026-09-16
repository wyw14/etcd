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

// Adversarial acceptance checks for precheck 530 ("带预览凭据的受保护租约撤销").
//
// These tests start from the frozen requirement text and try to falsify it.
// They are written to fail when the implementation has a real gap, not to
// confirm the implementation's own behaviour.

package lease_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap/zaptest"

	"go.etcd.io/etcd/pkg/v3/traceutil"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	"go.etcd.io/etcd/server/v3/lease"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/mvcc"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

// zzvAdvLessor builds a lessor whose deleter is left unwired, i.e. the
// degenerate configuration a bare lease.NewLessor has.
func zzvAdvLessor(t *testing.T) lease.Lessor {
	t.Helper()
	lg := zaptest.NewLogger(t)
	be, _ := betesting.NewDefaultTmpBackend(t)
	t.Cleanup(func() { betesting.Close(t, be) })
	cluster := membership.NewCluster(lg)
	cluster.SetBackend(schema.NewMembershipBackend(lg, be))
	le := lease.NewLessor(lg, be, cluster, lease.LessorConfig{MinLeaseTTL: 5})
	t.Cleanup(le.Stop)
	le.Promote(0)
	return le
}

// zzvAdvWired builds the configuration a running member uses: a real backend, a
// real key-value store, and the range deleter attached.
func zzvAdvWired(t *testing.T) (lease.Lessor, mvcc.KV) {
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
			t.Errorf("kv close: %v", err)
		}
	})
	le.Promote(0)
	return le, kv
}

func zzvAdvPut(t *testing.T, kv mvcc.KV, key, value string, id lease.LeaseID) {
	t.Helper()
	tw := kv.Write(traceutil.TODO())
	tw.Put([]byte(key), []byte(value), id)
	tw.End()
}

func zzvAdvDelete(t *testing.T, kv mvcc.KV, key string) {
	t.Helper()
	tw := kv.Write(traceutil.TODO())
	tw.DeleteRange([]byte(key), nil)
	tw.End()
}

func zzvAdvValue(t *testing.T, kv mvcc.KV, key string) (string, bool) {
	t.Helper()
	res, err := kv.Range(context.Background(), []byte(key), nil, mvcc.RangeOptions{})
	if err != nil {
		t.Fatalf("range %q: %v", key, err)
	}
	if len(res.KVs) == 0 {
		return "", false
	}
	return string(res.KVs[0].Value), true
}

// TestZZVAdv530WiredDoubleRevokeIsDefinite: after a successful protected revoke,
// repeating the operation, or revoking the same ID again, must yield a definite
// error and must not panic.
func TestZZVAdv530WiredDoubleRevokeIsDefinite(t *testing.T) {
	le, kv := zzvAdvWired(t)
	const id = lease.LeaseID(1)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	zzvAdvPut(t, kv, "adv-a", "1", id)
	zzvAdvPut(t, kv, "adv-b", "2", id)

	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("protected revoke: %v", err)
	}
	if le.Lookup(id) != nil {
		t.Fatal("the lease survived a successful protected revoke")
	}
	for _, key := range []string{"adv-a", "adv-b"} {
		if _, ok := zzvAdvValue(t, kv, key); ok {
			t.Errorf("previewed key %q was not deleted", key)
		}
	}

	if err := le.Revoke(id); !errors.Is(err, lease.ErrLeaseNotFound) {
		t.Errorf("ordinary revoke after a protected revoke = %v, want ErrLeaseNotFound", err)
	}
	if err := le.ProtectedRevoke(p.Token); !errors.Is(err, lease.ErrLeaseNotFound) {
		t.Errorf("repeat protected revoke = %v, want ErrLeaseNotFound", err)
	}
}

// TestZZVAdv530ABADetachReattachInvalidatesToken: detaching a key and binding it
// again restores the original key set, but the old credential must be dead.
func TestZZVAdv530ABADetachReattachInvalidatesToken(t *testing.T) {
	le, kv := zzvAdvWired(t)
	const id = lease.LeaseID(2)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	zzvAdvPut(t, kv, "adv-aba", "v1", id)

	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	zzvAdvDelete(t, kv, "adv-aba")             // detach
	zzvAdvPut(t, kv, "adv-aba", "v2", id)      // re-attach: same final key set

	err = le.ProtectedRevoke(p.Token)
	if !errors.Is(err, lease.ErrLeaseBindingsChanged) {
		t.Fatalf("ABA change returned %v, want ErrLeaseBindingsChanged", err)
	}
	if value, ok := zzvAdvValue(t, kv, "adv-aba"); !ok || value != "v2" {
		t.Fatalf("the re-bound key was disturbed: value=%q present=%v", value, ok)
	}
	if le.Lookup(id) == nil {
		t.Fatal("the lease was revoked although the credential was stale")
	}
}

// TestZZVAdv530RenewKeepsToken: renewing a lease must not invalidate the
// credential, because renewal is not a binding change.
func TestZZVAdv530RenewKeepsToken(t *testing.T) {
	le, kv := zzvAdvWired(t)
	const id = lease.LeaseID(3)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	zzvAdvPut(t, kv, "adv-renew", "v", id)

	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if _, err := le.Renew(id); err != nil {
		t.Fatalf("renew: %v", err)
	}
	// Rewriting the value of an already bound key is not a binding change either.
	zzvAdvPut(t, kv, "adv-renew", "v2", id)

	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("renew/value rewrite invalidated the credential: %v", err)
	}
	if _, ok := zzvAdvValue(t, kv, "adv-renew"); ok {
		t.Fatal("the previewed key survived the protected revoke")
	}
}

// TestZZVAdv530InstanceReuseInvalidatesToken: a credential taken for one granted
// lease must never revoke a later lease that reuses the same ID.
func TestZZVAdv530InstanceReuseInvalidatesToken(t *testing.T) {
	le, kv := zzvAdvWired(t)
	const id = lease.LeaseID(4)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("protected revoke: %v", err)
	}

	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	zzvAdvPut(t, kv, "adv-new-instance", "v", id)

	err = le.ProtectedRevoke(p.Token)
	if err == nil {
		t.Fatal("a stale credential revoked a different lease instance")
	}
	if !errors.Is(err, lease.ErrLeaseInstanceMismatch) && !errors.Is(err, lease.ErrLeaseNotFound) {
		t.Fatalf("stale credential returned %v, want a documented sentinel error", err)
	}
	if _, ok := zzvAdvValue(t, kv, "adv-new-instance"); !ok {
		t.Fatal("the new instance's key was deleted by a stale credential")
	}
	if le.Lookup(id) == nil {
		t.Fatal("the new lease instance was revoked by a stale credential")
	}
}

// TestZZVAdv530ConcurrentBindingMustNotPanic pins the freeze window open and
// performs a real key-value write bound to the frozen lease.
//
// The requirement says a binding change concurrent with the revoke must be
// resolved into a definite result. The implementation rejects such a binding by
// returning an error from Attach, but etcd's mvcc write path turns any Attach
// error into a panic ("unexpected error from lease Attach",
// server/storage/mvcc/kvstore_txn.go), and the etcdserver pre-check only tests
// Lookup != nil, which is still true while the lease is frozen.
//
// The writing side runs in a child process because a panic inside mvcc leaves
// the store locked and would deadlock this test's own cleanup.
func TestZZVAdv530ConcurrentBindingMustNotPanic(t *testing.T) {
	if os.Getenv("ZZVADV530_CHILD") == "1" {
		zzvAdvConcurrentBindingChild(t)
		return
	}
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestZZVAdv530ConcurrentBindingMustNotPanic$",
		"-test.timeout=90s",
	)
	cmd.Env = append(os.Environ(), "ZZVADV530_CHILD=1")
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil || strings.Contains(text, "panic:") {
		t.Fatalf("binding a key to a lease while its protected revoke is in flight crashed the member (err=%v):\n%s", err, text)
	}
}

func zzvAdvConcurrentBindingChild(t *testing.T) {
	lg := zaptest.NewLogger(t)
	be, _ := betesting.NewDefaultTmpBackend(t)
	cluster := membership.NewCluster(lg)
	cluster.SetBackend(schema.NewMembershipBackend(lg, be))
	le := lease.NewLessor(lg, be, cluster, lease.LessorConfig{MinLeaseTTL: 5})
	kv := mvcc.NewStore(lg, be, le, mvcc.StoreConfig{})
	le.Promote(0)

	const id = lease.LeaseID(5)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	zzvAdvPut(t, kv, "adv-frozen", "v", id)

	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	// Hold phase 2 open so the freeze window is observable, then bind a new key
	// to the same lease from the main goroutine.
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	le.SetRangeDeleter(func() lease.TxnDelete {
		once.Do(func() { close(entered) })
		<-release
		return kv.Write(traceutil.TODO())
	})

	go func() { _ = le.ProtectedRevoke(p.Token) }()
	<-entered

	zzvAdvPut(t, kv, "adv-concurrent", "v", id)
	close(release)
}

// TestZZVAdv530DegeneratePathLeavesNoPreviewState: on the path where no range
// deleter is wired the call must still not leave the lease frozen.
//
// Note: in this configuration a second ordinary Revoke of the same lease panics
// inside upstream Revoke (defer close(l.revokec) combined with the rd == nil
// early return that keeps the lease in the map). That branch is untouched by
// this change, so it is inherited behaviour and is not asserted here; what the
// feature itself must guarantee is that its own freeze is lifted.
func TestZZVAdv530DegeneratePathLeavesNoPreviewState(t *testing.T) {
	le := zzvAdvLessor(t)
	const id = lease.LeaseID(6)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("protected revoke: %v", err)
	}
	if err := le.Attach(id, []lease.LeaseItem{{Key: "adv-after"}}); err != nil {
		t.Fatalf("the lease was left frozen: a later binding failed with %v", err)
	}
}

// TestZZVAdv530PreviewAfterRevokeIsNotFound: previewing a lease that no longer
// exists must be a definite miss, and a token for it must not revoke anything.
func TestZZVAdv530PreviewAfterRevokeIsNotFound(t *testing.T) {
	le, kv := zzvAdvWired(t)
	const id = lease.LeaseID(7)
	if _, err := le.Grant(id, 600); err != nil {
		t.Fatalf("grant: %v", err)
	}
	zzvAdvPut(t, kv, "adv-gone", "v", id)
	p, err := le.PreviewProtectedRevoke(id)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("protected revoke: %v", err)
	}

	if _, err := le.PreviewProtectedRevoke(id); !errors.Is(err, lease.ErrLeaseNotFound) {
		t.Fatalf("preview of a revoked lease = %v, want ErrLeaseNotFound", err)
	}
}

// TestZZVAdv530TokenSurvivesUnrelatedLeaseActivity: work on other leases must
// not disturb a pending credential.
func TestZZVAdv530TokenSurvivesUnrelatedLeaseActivity(t *testing.T) {
	le, kv := zzvAdvWired(t)
	const (
		mine   = lease.LeaseID(8)
		theirs = lease.LeaseID(9)
	)
	if _, err := le.Grant(mine, 600); err != nil {
		t.Fatalf("grant mine: %v", err)
	}
	if _, err := le.Grant(theirs, 600); err != nil {
		t.Fatalf("grant theirs: %v", err)
	}
	zzvAdvPut(t, kv, "adv-mine", "v", mine)
	p, err := le.PreviewProtectedRevoke(mine)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	if _, err := le.Grant(lease.LeaseID(10), 600); err != nil {
		t.Fatalf("grant another: %v", err)
	}
	if _, err := le.Renew(theirs); err != nil {
		t.Fatalf("renew theirs: %v", err)
	}
	if err := le.Revoke(theirs); err != nil {
		t.Fatalf("revoke theirs: %v", err)
	}

	if err := le.ProtectedRevoke(p.Token); err != nil {
		t.Fatalf("unrelated lease activity invalidated the credential: %v", err)
	}
}
