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

// Independent acceptance verification for precheck 528.
//
// Unlike the submission's own suite, every fixture here comes from a real
// embedded etcd server, so the comparison is exercised against genuine
// snapshot data written by etcd itself rather than against a handcrafted
// bbolt layout.

package snapshot

import (
	"bytes"
	"context"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/server/v3/embed"
	"go.etcd.io/etcd/server/v3/etcdserver"
)

// zzv528RealDB starts an embedded etcd member, applies mutate to it and
// returns the path of the member backend database it produced.
func zzv528RealDB(t *testing.T, mutate func(t *testing.T, srv *etcdserver.EtcdServer)) string {
	t.Helper()

	cfg := embed.NewConfig()
	cfg.BackendBatchLimit = 1
	cfg.LogLevel = "fatal"
	cfg.Dir = t.TempDir()

	srv, err := embed.StartEtcd(cfg)
	require.NoError(t, err, "embedded etcd must start")
	defer srv.Close()

	select {
	case <-srv.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("embedded etcd did not become ready")
	}

	mutate(t, srv.Server)
	return filepath.Join(cfg.Dir, "member", "snap", "db")
}

// zzv528RealDBSnapshot does the same but also hands the database path to
// mutate, so callers can copy the file while the member is still running.
func zzv528RealDBSnapshot(t *testing.T, mutate func(t *testing.T, srv *etcdserver.EtcdServer, dbPath string)) string {
	t.Helper()

	cfg := embed.NewConfig()
	cfg.BackendBatchLimit = 1
	cfg.LogLevel = "fatal"
	cfg.Dir = t.TempDir()

	srv, err := embed.StartEtcd(cfg)
	require.NoError(t, err, "embedded etcd must start")
	defer srv.Close()

	select {
	case <-srv.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("embedded etcd did not become ready")
	}

	dbPath := filepath.Join(cfg.Dir, "member", "snap", "db")
	mutate(t, srv.Server, dbPath)
	return dbPath
}

func zzv528Put(t *testing.T, srv *etcdserver.EtcdServer, key string, value []byte, lease int64) int64 {
	t.Helper()
	resp, err := srv.Put(t.Context(), &etcdserverpb.PutRequest{
		Key: []byte(key), Value: value, Lease: lease,
	})
	require.NoError(t, err, "put %q", key)
	return resp.Header.Revision
}

func zzv528DeleteRange(t *testing.T, srv *etcdserver.EtcdServer, start, end string) {
	t.Helper()
	_, err := srv.DeleteRange(t.Context(), &etcdserverpb.DeleteRangeRequest{
		Key: []byte(start), RangeEnd: []byte(end),
	})
	require.NoError(t, err, "delete range %q-%q", start, end)
}

func zzv528Collect(t *testing.T, cfg CompareConfig) (CompareSummary, []KeyChange, error) {
	t.Helper()
	var changes []KeyChange
	summary, err := Compare(context.Background(), cfg, func(change KeyChange) error {
		copied := KeyChange{
			Type:                  change.Type,
			Key:                   append([]byte(nil), change.Key...),
			ValueChanged:          change.ValueChanged,
			CreateRevisionChanged: change.CreateRevisionChanged,
			ModRevisionChanged:    change.ModRevisionChanged,
			VersionChanged:        change.VersionChanged,
			LeaseChanged:          change.LeaseChanged,
		}
		if change.Before != nil {
			copied.Before = &KeyState{
				Value:          append([]byte(nil), change.Before.Value...),
				CreateRevision: change.Before.CreateRevision,
				ModRevision:    change.Before.ModRevision,
				Version:        change.Before.Version,
				Lease:          change.Before.Lease,
			}
		}
		if change.After != nil {
			copied.After = &KeyState{
				Value:          append([]byte(nil), change.After.Value...),
				CreateRevision: change.After.CreateRevision,
				ModRevision:    change.After.ModRevision,
				Version:        change.After.Version,
				Lease:          change.After.Lease,
			}
		}
		changes = append(changes, copied)
		return nil
	})
	return summary, changes, err
}

func zzv528ChangeByKey(t *testing.T, changes []KeyChange, key string) KeyChange {
	t.Helper()
	for _, change := range changes {
		if string(change.Key) == key {
			return change
		}
	}
	t.Fatalf("no change reported for key %q; reported=%v", key, zzv528Keys(changes))
	return KeyChange{}
}

func zzv528Keys(changes []KeyChange) []string {
	keys := make([]string, 0, len(changes))
	for _, change := range changes {
		keys = append(keys, string(change.Key))
	}
	return keys
}

// buildBase writes the reference state used by most subtests.
func zzv528BuildBase(t *testing.T) string {
	return zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528Put(t, srv, "alpha", []byte("one"), 0)
		zzv528Put(t, srv, "gamma", []byte("g"), 0)
		zzv528Put(t, srv, "old", []byte("oldv"), 0)
	})
}

// buildChanged writes: alpha unchanged, gamma kept byte-identical but rewritten
// inside a transaction, beta added, old deleted, plus a lease-bound key.
func zzv528BuildChanged(t *testing.T) string {
	return zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528Put(t, srv, "alpha", []byte("one"), 0)
		zzv528Put(t, srv, "gamma", []byte("g"), 0)
		zzv528Put(t, srv, "old", []byte("oldv"), 0)
		zzv528Put(t, srv, "beta", []byte("two"), 0)
		zzv528DeleteRange(t, srv, "old", "old\x00")
		lease, err := srv.LeaseGrant(t.Context(), &etcdserverpb.LeaseGrantRequest{TTL: 600})
		require.NoError(t, err)
		zzv528Put(t, srv, "leased", []byte("l"), lease.ID)
	})
}

func TestZZV528RealSnapshotComparison(t *testing.T) {
	base := zzv528BuildBase(t)
	changed := zzv528BuildChanged(t)

	baseStatus, err := NewV3(zap.NewNop()).Status(base)
	require.NoError(t, err)
	changedStatus, err := NewV3(zap.NewNop()).Status(changed)
	require.NoError(t, err)
	t.Logf("base revision=%d keys=%d hash=%#x", baseStatus.Revision, baseStatus.TotalKey, baseStatus.Hash)
	t.Logf("changed revision=%d keys=%d hash=%#x", changedStatus.Revision, changedStatus.TotalKey, changedStatus.Hash)

	summary, changes, err := zzv528Collect(t, CompareConfig{
		SnapshotAPath: base, SnapshotBPath: changed,
	})
	require.NoError(t, err)

	// Rubric 1: both sides report the revision actually read and the range.
	assert.Equal(t, int64(0), summary.A.RequestedRevision)
	assert.Equal(t, int64(0), summary.B.RequestedRevision)
	assert.Equal(t, baseStatus.Revision, summary.A.LatestRevision)
	assert.Equal(t, changedStatus.Revision, summary.B.LatestRevision)
	assert.Equal(t, baseStatus.Revision, summary.A.Revision)
	assert.Equal(t, changedStatus.Revision, summary.B.Revision)
	assert.Empty(t, summary.Range.Start)
	assert.Empty(t, summary.Range.End)
	assert.False(t, summary.Equal)

	// Rubric 2: additions, deletions and modifications in key byte order.
	assert.Equal(t, []string{"beta", "leased", "old"}, zzv528Keys(changes))
	assert.Equal(t, ChangeAdded, zzv528ChangeByKey(t, changes, "beta").Type)
	assert.Equal(t, ChangeAdded, zzv528ChangeByKey(t, changes, "leased").Type)
	assert.Equal(t, ChangeDeleted, zzv528ChangeByKey(t, changes, "old").Type)

	deleted := zzv528ChangeByKey(t, changes, "old")
	require.NotNil(t, deleted.Before)
	assert.Nil(t, deleted.After)
	assert.Equal(t, []byte("oldv"), deleted.Before.Value)

	leased := zzv528ChangeByKey(t, changes, "leased")
	require.NotNil(t, leased.After)
	assert.NotZero(t, leased.After.Lease, "lease binding must be reported")

	// Rubric 2: modification versus addition/deletion must stay distinguishable.
	// alpha, gamma and old are unchanged on side A while beta, the leased key
	// and the "old" deletion differ, so only added/deleted may be reported here.
	assert.Equal(t, 0, summary.ValueChanged)
	assert.Equal(t, 0, summary.CreateRevisionChanged)
	assert.Equal(t, 0, summary.ModRevisionChanged)
	assert.Equal(t, 0, summary.VersionChanged)
	assert.Equal(t, 0, summary.LeaseChanged)
	assert.Equal(t, 2, summary.Added)
	assert.Equal(t, 1, summary.Deleted)
	assert.Equal(t, 0, summary.Modified)
	assert.Equal(t, baseStatus.TotalKey, summary.TotalKeysA)
	assert.Equal(t, changedStatus.TotalKey, summary.TotalKeysB)

	// Rubric 2: each attribute dimension is reported on its own. Comparing two
	// revisions of the same real database exercises the modified path with a
	// value change, a lease binding change and no change at all.
	t.Run("attribute dimensions", func(t *testing.T) {
		t.Run("value change only", func(t *testing.T) {
			sideA := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
				zzv528Put(t, srv, "gamma", []byte("g"), 0)
			})
			sideB := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
				zzv528Put(t, srv, "gamma", []byte("g"), 0)
				zzv528Put(t, srv, "gamma", []byte("changed"), 0)
			})
			summary, changes, err := zzv528Collect(t, CompareConfig{SnapshotAPath: sideA, SnapshotBPath: sideB})
			require.NoError(t, err)
			require.Len(t, changes, 1)
			assert.Equal(t, ChangeModified, changes[0].Type)
			assert.True(t, changes[0].ValueChanged)
			assert.False(t, changes[0].CreateRevisionChanged)
			assert.True(t, changes[0].ModRevisionChanged)
			assert.True(t, changes[0].VersionChanged)
			assert.False(t, changes[0].LeaseChanged)
			assert.Equal(t, []byte("g"), changes[0].Before.Value)
			assert.Equal(t, []byte("changed"), changes[0].After.Value)
			assert.Equal(t, int64(0), changes[0].Before.Lease)
			assert.Equal(t, int64(0), changes[0].After.Lease)
			assert.Equal(t, 1, summary.Modified)
			assert.Equal(t, 1, summary.ValueChanged)
			assert.Equal(t, 0, summary.CreateRevisionChanged)
			assert.Equal(t, 1, summary.ModRevisionChanged)
			assert.Equal(t, 1, summary.VersionChanged)
			assert.Equal(t, 0, summary.LeaseChanged)
		})

		t.Run("lease binding change only", func(t *testing.T) {
			sideA := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
				zzv528Put(t, srv, "bound", []byte("same"), 0)
			})
			sideB := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
				lease, err := srv.LeaseGrant(t.Context(), &etcdserverpb.LeaseGrantRequest{TTL: 600})
				require.NoError(t, err)
				zzv528Put(t, srv, "bound", []byte("same"), lease.ID)
			})
			summary, changes, err := zzv528Collect(t, CompareConfig{SnapshotAPath: sideA, SnapshotBPath: sideB})
			require.NoError(t, err)
			require.Len(t, changes, 1)
			assert.Equal(t, ChangeModified, changes[0].Type)
			assert.False(t, changes[0].ValueChanged, "identical value bytes are not a value change")
			assert.True(t, changes[0].LeaseChanged)
			assert.Equal(t, int64(0), changes[0].Before.Lease)
			assert.NotZero(t, changes[0].After.Lease)
			assert.Equal(t, 1, summary.LeaseChanged)
			assert.Equal(t, 0, summary.ValueChanged)
		})

		t.Run("all five attribute dimensions on one history", func(t *testing.T) {
			// A single real database exposes every dimension the rubric asks
			// for: create revision, mod revision, version, value and lease.
			var revCreate, revValue, revLease, revRecreate int64
			var leaseID int64
			dbPath := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
				revCreate = zzv528Put(t, srv, "attr", []byte("v1"), 0)
				revValue = zzv528Put(t, srv, "attr", []byte("v2"), 0)

				lease, err := srv.LeaseGrant(t.Context(), &etcdserverpb.LeaseGrantRequest{TTL: 600})
				require.NoError(t, err)
				leaseID = lease.ID
				revLease = zzv528Put(t, srv, "attr", []byte("v2"), lease.ID)

				resp, err := srv.DeleteRange(t.Context(), &etcdserverpb.DeleteRangeRequest{
					Key: []byte("attr"), RangeEnd: []byte("attr\x00"),
				})
				require.NoError(t, err)
				t.Logf("delete at revision %d", resp.Header.Revision)
				revRecreate = zzv528Put(t, srv, "attr", []byte("v2"), 0)
			})
			t.Logf("create=%d value=%d lease=%d recreate=%d leaseID=%d",
				revCreate, revValue, revLease, revRecreate, leaseID)

			t.Run("value and version change", func(t *testing.T) {
				summary, changes, err := zzv528Collect(t, CompareConfig{
					SnapshotAPath: dbPath, RevisionA: revCreate,
					SnapshotBPath: dbPath, RevisionB: revValue,
				})
				require.NoError(t, err)
				require.Len(t, changes, 1)
				assert.Equal(t, ChangeModified, changes[0].Type)
				assert.True(t, changes[0].ValueChanged)
				assert.True(t, changes[0].VersionChanged)
				assert.True(t, changes[0].ModRevisionChanged)
				assert.False(t, changes[0].CreateRevisionChanged)
				assert.False(t, changes[0].LeaseChanged)
				assert.Equal(t, []byte("v1"), changes[0].Before.Value)
				assert.Equal(t, []byte("v2"), changes[0].After.Value)
				assert.Equal(t, int64(1), changes[0].Before.Version)
				assert.Equal(t, int64(2), changes[0].After.Version)
				assert.Equal(t, 1, summary.ValueChanged)
				assert.Equal(t, 1, summary.VersionChanged)
				assert.Equal(t, 1, summary.ModRevisionChanged)
			})

			t.Run("lease binding change without a value change", func(t *testing.T) {
				summary, changes, err := zzv528Collect(t, CompareConfig{
					SnapshotAPath: dbPath, RevisionA: revValue,
					SnapshotBPath: dbPath, RevisionB: revLease,
				})
				require.NoError(t, err)
				require.Len(t, changes, 1)
				assert.Equal(t, ChangeModified, changes[0].Type)
				assert.False(t, changes[0].ValueChanged, "the value bytes are identical")
				assert.True(t, changes[0].LeaseChanged)
				assert.Equal(t, int64(0), changes[0].Before.Lease)
				assert.Equal(t, leaseID, changes[0].After.Lease)
				assert.Equal(t, 1, summary.LeaseChanged)
				assert.Equal(t, 0, summary.ValueChanged)
			})

			t.Run("create revision change after a delete and recreate", func(t *testing.T) {
				summary, changes, err := zzv528Collect(t, CompareConfig{
					SnapshotAPath: dbPath, RevisionA: revLease,
					SnapshotBPath: dbPath, RevisionB: revRecreate,
					RangeStart:    []byte("attr"), RangeEnd: []byte("attr\x00"),
				})
				require.NoError(t, err)
				t.Logf("changes: %v; summary=%+v", zzv528Keys(changes), summary)
				require.Len(t, changes, 1)
				assert.Equal(t, ChangeModified, changes[0].Type,
					"the key is live on both sides, so this is a modification")
				assert.True(t, changes[0].CreateRevisionChanged,
					"the recreate gives the key a new create revision")
				require.NotNil(t, changes[0].Before)
				require.NotNil(t, changes[0].After)
				assert.Equal(t, revCreate, changes[0].Before.CreateRevision)
				assert.Equal(t, revRecreate, changes[0].After.CreateRevision)
				assert.Equal(t, int64(1), changes[0].After.Version,
					"the recreated key restarts at version 1")
				assert.False(t, changes[0].ValueChanged, "the value bytes are identical")
				assert.Zero(t, changes[0].After.Lease, "the delete released the lease binding")
				assert.Equal(t, 1, summary.CreateRevisionChanged)
				assert.Equal(t, 0, summary.ValueChanged)
			})
		})
	})

	// Rubric 5: input files stay byte-identical.
	baseBytes, err := os.ReadFile(base)
	require.NoError(t, err)
	changedBytes, err := os.ReadFile(changed)
	require.NoError(t, err)
	_, _, err = zzv528Collect(t, CompareConfig{SnapshotAPath: base, SnapshotBPath: changed})
	require.NoError(t, err)
	baseAfter, err := os.ReadFile(base)
	require.NoError(t, err)
	changedAfter, err := os.ReadFile(changed)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(baseBytes, baseAfter), "snapshot A must not be modified")
	assert.True(t, bytes.Equal(changedBytes, changedAfter), "snapshot B must not be modified")
}

func TestZZV528KeyRangeAndRevisionSelection(t *testing.T) {
	base := zzv528BuildBase(t)
	changed := zzv528BuildChanged(t)

	baseStatus, err := NewV3(zap.NewNop()).Status(base)
	require.NoError(t, err)
	changedStatus, err := NewV3(zap.NewNop()).Status(changed)
	require.NoError(t, err)
	_, full, err := zzv528Collect(t, CompareConfig{SnapshotAPath: base, SnapshotBPath: changed})
	require.NoError(t, err)
	t.Logf("base rev=%d keys=%d; changed rev=%d keys=%d; full-range changes=%v",
		baseStatus.Revision, baseStatus.TotalKey, changedStatus.Revision, changedStatus.TotalKey,
		zzv528Keys(full))

	t.Run("half-open range keeps only alpha and beta", func(t *testing.T) {
		summary, changes, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: base, SnapshotBPath: changed,
			RangeStart: []byte("alpha"), RangeEnd: []byte("gamma"),
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"beta"}, zzv528Keys(changes))
		assert.Equal(t, []byte("alpha"), summary.Range.Start)
		assert.Equal(t, []byte("gamma"), summary.Range.End)
		assert.Equal(t, 1, summary.TotalKeysA)
		assert.Equal(t, 2, summary.TotalKeysB)
	})

	t.Run("single zero byte range end means open bound", func(t *testing.T) {
		_, changes, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: base, SnapshotBPath: changed,
			RangeStart: []byte("gamma"), RangeEnd: []byte{0},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"leased", "old"}, zzv528Keys(changes))
	})

	t.Run("empty range start means first key", func(t *testing.T) {
		summary, changes, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: base, SnapshotBPath: changed, RangeEnd: []byte("gamma"),
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"beta"}, zzv528Keys(changes),
			"alpha is unchanged on both sides; only beta differs inside the range")
		assert.Equal(t, 1, summary.TotalKeysA, "only alpha is live below the exclusive end")
		assert.Equal(t, 2, summary.TotalKeysB, "alpha and beta are live below the exclusive end")
		assert.Empty(t, summary.Range.Start)
	})

	t.Run("one file compared with itself is equal at every revision", func(t *testing.T) {
		status, err := NewV3(zap.NewNop()).Status(base)
		require.NoError(t, err)
		for _, rev := range []int64{1, 2, 3, status.Revision} {
			summary, changes, err := zzv528Collect(t, CompareConfig{
				SnapshotAPath: base, RevisionA: rev,
				SnapshotBPath: base, RevisionB: rev,
			})
			require.NoError(t, err, "revision %d", rev)
			assert.Empty(t, zzv528Keys(changes), "revision %d", rev)
			assert.True(t, summary.Equal, "revision %d", rev)
			assert.Equal(t, rev, summary.A.Revision)
			assert.Equal(t, rev, summary.B.Revision)
		}
	})

	t.Run("invalid range is rejected before reporting anything", func(t *testing.T) {
		called := false
		_, err := Compare(context.Background(), CompareConfig{
			SnapshotAPath: base, SnapshotBPath: base,
			RangeStart: []byte("z"), RangeEnd: []byte("a"),
		}, func(KeyChange) error { called = true; return nil })
		require.Error(t, err)
		assert.False(t, called)
	})
}

// TestZZV528LogicalHistory walks a key through put, put, put, delete, recreate
// plus a two-put transaction, then reads the same database at the revisions the
// server itself reported. It proves the comparison interprets each selected
// revision instead of following the physical record layout.
func TestZZV528LogicalHistory(t *testing.T) {
	var (
		revPut1, revPut2, revPut3, revDelete, revRecreate, revTxn int64
	)
	dbPath := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		revPut1 = zzv528Put(t, srv, "k", []byte("v1"), 0)
		revPut2 = zzv528Put(t, srv, "k", []byte("v2"), 0)
		revPut3 = zzv528Put(t, srv, "k", []byte("v3"), 0)

		resp, err := srv.DeleteRange(t.Context(), &etcdserverpb.DeleteRangeRequest{
			Key: []byte("k"), RangeEnd: []byte("k\x00"),
		})
		require.NoError(t, err)
		revDelete = resp.Header.Revision

		revRecreate = zzv528Put(t, srv, "k", []byte("v4"), 0)

		txnResp, err := srv.Txn(t.Context(), &etcdserverpb.TxnRequest{
			Success: []*etcdserverpb.RequestOp{
				{Request: &etcdserverpb.RequestOp_RequestPut{
					RequestPut: &etcdserverpb.PutRequest{Key: []byte("multi"), Value: []byte("m1")},
				}},
				{Request: &etcdserverpb.RequestOp_RequestPut{
					RequestPut: &etcdserverpb.PutRequest{Key: []byte("multi"), Value: []byte("m2")},
				}},
			},
		})
		require.NoError(t, err)
		revTxn = txnResp.Header.Revision
	})

	status, err := NewV3(zap.NewNop()).Status(dbPath)
	require.NoError(t, err)
	t.Logf("revisions: put1=%d put2=%d put3=%d delete=%d recreate=%d txn=%d latest=%d totalKeys=%d",
		revPut1, revPut2, revPut3, revDelete, revRecreate, revTxn, status.Revision, status.TotalKey)

	require.Equal(t, revTxn, status.Revision)
	require.Equal(t, int64(2), int64(status.TotalKey))

	t.Run("revision before the delete still sees the third value", func(t *testing.T) {
		summary, changes, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: dbPath, RevisionA: revPut3,
			SnapshotBPath: dbPath, RevisionB: revTxn,
		})
		require.NoError(t, err)
		assert.Equal(t, revPut3, summary.A.Revision)
		assert.Equal(t, revTxn, summary.B.Revision)

		k := zzv528ChangeByKey(t, changes, "k")
		require.Equal(t, ChangeModified, k.Type)
		require.NotNil(t, k.Before)
		require.NotNil(t, k.After)
		assert.Equal(t, []byte("v3"), k.Before.Value)
		assert.Equal(t, []byte("v4"), k.After.Value)
		assert.Equal(t, revPut3, k.Before.ModRevision)
		assert.Equal(t, int64(3), k.Before.Version)
		assert.Equal(t, int64(1), k.After.Version, "the recreated key restarts at version 1")
		assert.True(t, k.CreateRevisionChanged, "the recreate has a new create revision")
		assert.True(t, k.ModRevisionChanged)

		multi := zzv528ChangeByKey(t, changes, "multi")
		assert.Equal(t, ChangeAdded, multi.Type)
		assert.Equal(t, []byte("m2"), multi.After.Value, "the last write of the transaction is the effective one")
	})

	t.Run("a revision while the key is deleted reports it as added later", func(t *testing.T) {
		_, changes, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: dbPath, RevisionA: revDelete,
			SnapshotBPath: dbPath, RevisionB: revTxn,
		})
		require.NoError(t, err)
		k := zzv528ChangeByKey(t, changes, "k")
		require.Equal(t, ChangeAdded, k.Type)
		assert.Nil(t, k.Before, "a deleted key has no state on side A")
		require.NotNil(t, k.After)
		assert.Equal(t, []byte("v4"), k.After.Value)
	})

	t.Run("comparing two consecutive writes reports the intermediate value", func(t *testing.T) {
		_, changes, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: dbPath, RevisionA: revPut1,
			SnapshotBPath: dbPath, RevisionB: revPut2,
		})
		require.NoError(t, err)
		require.Len(t, changes, 1)
		assert.Equal(t, []byte("v1"), changes[0].Before.Value)
		assert.Equal(t, []byte("v2"), changes[0].After.Value)
		assert.Equal(t, revPut1, changes[0].Before.CreateRevision)
		assert.Equal(t, revPut2, changes[0].After.ModRevision)
		assert.Equal(t, int64(1), changes[0].Before.Version)
		assert.Equal(t, int64(2), changes[0].After.Version)
	})

	t.Run("same logical state reached through different histories", func(t *testing.T) {
		// A key that was written, deleted and recreated keeps the same visible
		// value but a new create revision, so it must be reported. The
		// complementary "identical logical state, different physical layout"
		// case is covered by TestZZV528PhysicalLayoutIsNotADifference.
		fresh := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
			zzv528Put(t, srv, "k", []byte("v4"), 0)
		})
		summary, changes, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: dbPath, RevisionA: revTxn,
			SnapshotBPath: fresh,
			RangeStart:    []byte("k"), RangeEnd: []byte("k\x00"),
		})
		require.NoError(t, err)
		assert.False(t, summary.Equal)
		require.Len(t, changes, 1)
		assert.True(t, changes[0].CreateRevisionChanged,
			"the recreate has a different create revision")
		assert.False(t, changes[0].ValueChanged, "the visible value is identical")
		assert.Equal(t, 1, summary.CreateRevisionChanged)
		assert.Equal(t, 0, summary.ValueChanged)
	})
}

// TestZZV528PhysicalLayoutIsNotADifference builds two files that hold exactly
// the same logical keyspace at the same revisions but differ physically: one is
// the untouched copy and the other was compacted, which removes superseded
// revisions, frees pages and rewrites the bolt layout.
func TestZZV528PhysicalLayoutIsNotADifference(t *testing.T) {
	backupDir := t.TempDir()
	backupPath := filepath.Join(backupDir, "before-compaction.db")

	var compactRevision int64
	compacted := zzv528RealDBSnapshot(t, func(t *testing.T, srv *etcdserver.EtcdServer, dbPath string) {
		for i := 0; i < 30; i++ {
			zzv528Put(t, srv, "recycled", []byte("v"+strconv.Itoa(i)), 0)
		}
		zzv528Put(t, srv, "business", []byte("final"), 0)
		zzv528Put(t, srv, "other", []byte("o"), 0)
		zzv528DeleteRange(t, srv, "other", "other\x00")
		zzv528Put(t, srv, "kept", []byte("k"), 0)

		// Snapshot the identical logical state before compaction touches it.
		source, err := os.ReadFile(dbPath)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(backupPath, source, 0o400))

		rangeResp, err := srv.Range(t.Context(), &etcdserverpb.RangeRequest{Key: []byte{0}})
		require.NoError(t, err)
		currentRevision := rangeResp.Header.Revision
		require.Greater(t, currentRevision, int64(2))

		resp, err := srv.Compact(t.Context(), &etcdserverpb.CompactionRequest{
			Revision: currentRevision - 1, Physical: true,
		})
		require.NoError(t, err)
		compactRevision = resp.Header.Revision
	})

	backupStatus, err := NewV3(zap.NewNop()).Status(backupPath)
	require.NoError(t, err)
	compactedStatus, err := NewV3(zap.NewNop()).Status(compacted)
	require.NoError(t, err)
	backupInfo, err := os.Stat(backupPath)
	require.NoError(t, err)
	compactedInfo, err := os.Stat(compacted)
	require.NoError(t, err)

	t.Logf("backup:    revision=%d keys=%d size=%d hash=%#x", backupStatus.Revision, backupStatus.TotalKey, backupInfo.Size(), backupStatus.Hash)
	t.Logf("compacted: revision=%d keys=%d size=%d hash=%#x", compactedStatus.Revision, compactedStatus.TotalKey, compactedInfo.Size(), compactedStatus.Hash)
	require.Equal(t, backupStatus.Revision, compactedStatus.Revision,
		"compaction must not change the logical revision")
	require.Equal(t, backupStatus.TotalKey, compactedStatus.TotalKey,
		"compaction must not change the visible key count")
	require.NotEqual(t, backupStatus.Hash, compactedStatus.Hash,
		"the two files must differ physically for this test to mean anything")

	summary, changes, err := zzv528Collect(t, CompareConfig{
		SnapshotAPath: backupPath, SnapshotBPath: compacted,
	})
	require.NoError(t, err)
	assert.Empty(t, zzv528Keys(changes),
		"identical logical data must not be reported as a business difference")
	assert.True(t, summary.Equal)
	assert.Equal(t, 3, summary.TotalKeysA, "recycled, business and kept stay visible")
	assert.Equal(t, 3, summary.TotalKeysB)
	assert.True(t, summary.A.CompactRevision < 0, "the backup was never compacted")
	assert.NotEqual(t, int64(-1), summary.B.CompactRevision,
		"the compacted side must report its compaction revision")
	t.Logf("compaction revision reported by side B: %d (compact request revision %d)",
		summary.B.CompactRevision, compactRevision)

	// Rubric 5: a revision below the compaction point fails explicitly instead
	// of publishing a partial report.
	called := false
	_, err = Compare(context.Background(), CompareConfig{
		SnapshotAPath: compacted, RevisionA: 2,
		SnapshotBPath: backupPath,
	}, func(KeyChange) error { called = true; return nil })
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRevisionCompacted)
	assert.False(t, called, "a compacted revision must not publish a partial result")

	// The compaction boundary itself stays readable: revision 34 is exactly
	// where the compacted side becomes readable again, so comparing it with the
	// same side at its latest revision only reports keys written after it.
	boundarySummary, boundaryChanges, err := zzv528Collect(t, CompareConfig{
		SnapshotAPath: compacted, RevisionA: summary.B.CompactRevision,
		SnapshotBPath: compacted,
	})
	require.NoError(t, err)
	assert.Equal(t, summary.B.CompactRevision, boundarySummary.A.Revision)
	assert.Equal(t, summary.B.CompactRevision, boundarySummary.A.CompactRevision)
	assert.False(t, boundarySummary.Equal, "the last write happened after the compaction point")
	assert.Equal(t, []string{"kept"}, zzv528Keys(boundaryChanges),
		"only the write after the compaction boundary is missing at that revision")
}

func TestZZV528ExplicitFailureAndBinaryLossless(t *testing.T) {
	dbPath := zzv528BuildBase(t)
	status, err := NewV3(zap.NewNop()).Status(dbPath)
	require.NoError(t, err)

	t.Run("future revision on either side is rejected", func(t *testing.T) {
		for _, cfg := range []CompareConfig{
			{SnapshotAPath: dbPath, RevisionA: status.Revision + 100, SnapshotBPath: dbPath},
			{SnapshotAPath: dbPath, SnapshotBPath: dbPath, RevisionB: status.Revision + 100},
		} {
			called := false
			_, err := Compare(context.Background(), cfg, func(KeyChange) error { called = true; return nil })
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrRevisionInFuture)
			assert.False(t, called)
		}
	})

	t.Run("missing file is rejected", func(t *testing.T) {
		_, err := Compare(context.Background(), CompareConfig{
			SnapshotAPath: filepath.Join(t.TempDir(), "absent.db"), SnapshotBPath: dbPath,
		}, nil)
		require.Error(t, err)
	})

	t.Run("corrupt snapshot is rejected", func(t *testing.T) {
		corrupt := filepath.Join(t.TempDir(), "corrupt.db")
		require.NoError(t, os.WriteFile(corrupt, []byte("this is not a bbolt database"), 0o400))
		called := false
		_, err := Compare(context.Background(), CompareConfig{
			SnapshotAPath: corrupt, SnapshotBPath: dbPath,
		}, func(KeyChange) error { called = true; return nil })
		require.Error(t, err)
		assert.False(t, called)
	})

	t.Run("cancellation stops the comparison", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Compare(ctx, CompareConfig{
			SnapshotAPath: dbPath, SnapshotBPath: dbPath,
		}, func(KeyChange) error { return nil })
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("binary keys and values survive the round trip", func(t *testing.T) {
		binary := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
			zzv528Put(t, srv, "plain", []byte("v"), 0)
			zzv528Put(t, srv, string([]byte{0x00, 0x01, 0xff}), []byte{0xfe, 0x00, 0x80, 0xff}, 0)
			zzv528Put(t, srv, string([]byte{0xff, 0xfe}), []byte{0x00}, 0)
		})

		_, all, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: dbPath, SnapshotBPath: binary,
		})
		require.NoError(t, err)

		// The reference side also holds alpha/gamma/old, so restrict the
		// assertion to the keys this subtest introduced.
		var binaryChanges []KeyChange
		for _, change := range all {
			switch string(change.Key) {
			case "plain", string([]byte{0x00, 0x01, 0xff}), string([]byte{0xff, 0xfe}):
				binaryChanges = append(binaryChanges, change)
			}
		}
		require.Equal(t,
			[]string{string([]byte{0x00, 0x01, 0xff}), "plain", string([]byte{0xff, 0xfe})},
			zzv528Keys(binaryChanges),
			"keys must be ordered by raw byte value")
		assert.Equal(t, ChangeAdded, zzv528ChangeByKey(t, binaryChanges, "plain").Type)

		added := zzv528ChangeByKey(t, binaryChanges, string([]byte{0x00, 0x01, 0xff}))
		require.Equal(t, ChangeAdded, added.Type)
		assert.Equal(t, []byte{0xfe, 0x00, 0x80, 0xff}, added.After.Value)

		high := zzv528ChangeByKey(t, binaryChanges, string([]byte{0xff, 0xfe}))
		require.Equal(t, ChangeAdded, high.Type)
		assert.Equal(t, []byte{0x00}, high.After.Value)

		// A comparison restricted to the non-UTF-8 key reports exactly one change.
		_, ranged, err := zzv528Collect(t, CompareConfig{
			SnapshotAPath: dbPath, SnapshotBPath: binary,
			RangeStart: []byte{0x00, 0x01, 0xff}, RangeEnd: []byte{0x00, 0x01, 0xff, 0x00},
		})
		require.NoError(t, err)
		require.Len(t, ranged, 1)
		assert.Equal(t, []byte{0x00, 0x01, 0xff}, ranged[0].Key)
		assert.Equal(t, []byte{0xfe, 0x00, 0x80, 0xff}, ranged[0].After.Value)
	})
}

// TestZZV528MemoryDoesNotScaleWithValueVolume compares two snapshots that hold
// far more value bytes than the allowed heap growth, so a bounded
// implementation cannot pass by holding the values.
//
// The large pair holds far more value bytes per side than the heap ceiling, so
// a comparison that retains values would allocate well past it. The small pair
// is measured first only to show the fixture scale differs by orders of
// magnitude.
func TestZZV528MemoryDoesNotScaleWithValueVolume(t *testing.T) {
	const (
		keys        = 32
		valueSize   = 1 << 20
		heapCeiling = 64 << 20
	)

	value := bytes.Repeat([]byte("etcd-snapshot-diff-"), valueSize/len("etcd-snapshot-diff-")+1)[:valueSize]
	fill := func(t *testing.T, srv *etcdserver.EtcdServer) {
		for i := 0; i < keys; i++ {
			key := "bulk-" + strconv.Itoa(i)
			zzv528Put(t, srv, key, value, 0)
			zzv528Put(t, srv, key, value, 0)
		}
	}

	sideA := zzv528RealDB(t, fill)
	sideB := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		fill(t, srv)
		zzv528Put(t, srv, "bulk-0", []byte("changed"), 0)
	})

	smallA := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528Put(t, srv, "bulk-0", []byte("v"), 0)
	})
	smallB := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528Put(t, srv, "bulk-0", []byte("changed"), 0)
	})

	measure := func(tag, pathA, pathB string) (CompareSummary, int64, int64) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		// Sample the live heap while the comparison runs: retaining the values
		// would push this peak towards the compared volume.
		stop := make(chan struct{})
		peak := make(chan uint64, 1)
		go func() {
			var highest uint64
			for {
				select {
				case <-stop:
					peak <- highest
					return
				default:
				}
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				if sample.HeapAlloc > highest {
					highest = sample.HeapAlloc
				}
				time.Sleep(time.Millisecond)
			}
		}()

		summary, changes, err := zzv528Collect(t, CompareConfig{SnapshotAPath: pathA, SnapshotBPath: pathB})
		close(stop)
		require.NoError(t, err)
		highest := <-peak

		runtime.GC()
		runtime.ReadMemStats(&after)
		encodedPeak := int64(highest) - int64(before.HeapAlloc)
		retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		t.Logf("%s: keysA=%d keysB=%d changes=%d liveHeapAboveBaseline=%d retainedAfter=%d totalAllocDelta=%d",
			tag, summary.TotalKeysA, summary.TotalKeysB, len(changes),
			encodedPeak, retained, after.TotalAlloc-before.TotalAlloc)
		return summary, encodedPeak, retained
	}

	_, _, _ = measure("small pair", smallA, smallB)
	summary, livePeak, retained := measure("large pair", sideA, sideB)

	_, changes, err := zzv528Collect(t, CompareConfig{SnapshotAPath: sideA, SnapshotBPath: sideB})
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, "bulk-0", string(changes[0].Key))
	assert.True(t, changes[0].ValueChanged)
	assert.Equal(t, []byte("changed"), changes[0].After.Value)
	assert.Equal(t, []byte(value), changes[0].Before.Value, "the large value must survive intact")
	assert.Equal(t, keys, summary.TotalKeysA)
	assert.Equal(t, keys, summary.TotalKeysB)

	totalValueBytes := int64(keys) * int64(valueSize)
	t.Logf("compared value volume per side: %d bytes; live heap peak above baseline: %d bytes",
		totalValueBytes, livePeak)

	// Both sides together hold 2*totalValueBytes of values. Retaining them
	// would keep the live heap at or above that volume; a streaming
	// comparison keeps only one value at a time and stays far below it.
	bothSides := 2 * totalValueBytes
	assert.Less(t, livePeak*2, bothSides,
		"live heap must stay well below the volume of both sides together")
	assert.Less(t, livePeak, int64(3*(1<<20))*int64(keys)/2,
		"live heap must not scale with the compared value volume")
	assert.Less(t, retained, int64(heapCeiling)/16,
		"nothing may stay retained after the comparison")
}

// TestZZV528SnapshotFileFingerprintIsStable guards the read-only contract at
// the byte level: comparing twice must leave both files with the same content
// hash and the same modification time.
func TestZZV528SnapshotFileFingerprintIsStable(t *testing.T) {
	sideA := zzv528BuildBase(t)
	sideB := zzv528BuildChanged(t)

	fingerprint := func(path string) (uint64, time.Time, int64) {
		info, err := os.Stat(path)
		require.NoError(t, err)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		h := fnv.New64a()
		_, err = h.Write(data)
		require.NoError(t, err)
		return h.Sum64(), info.ModTime(), info.Size()
	}

	hashA, modA, sizeA := fingerprint(sideA)
	hashB, modB, sizeB := fingerprint(sideB)

	for i := 0; i < 3; i++ {
		_, _, err := zzv528Collect(t, CompareConfig{SnapshotAPath: sideA, SnapshotBPath: sideB})
		require.NoError(t, err)
	}

	gotHashA, gotModA, gotSizeA := fingerprint(sideA)
	gotHashB, gotModB, gotSizeB := fingerprint(sideB)
	assert.Equal(t, hashA, gotHashA)
	assert.Equal(t, hashB, gotHashB)
	assert.Equal(t, sizeA, gotSizeA)
	assert.Equal(t, sizeB, gotSizeB)
	assert.Equal(t, modA, gotModA, "input modification time must not change")
	assert.Equal(t, modB, gotModB, "input modification time must not change")
}

// TestZZV528DeterministicOrdering repeats the same comparison to prove the
// reported order and counters are stable.
func TestZZV528DeterministicOrdering(t *testing.T) {
	sideA := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		for i := 0; i < 40; i++ {
			zzv528Put(t, srv, "seed-"+strconv.Itoa(i), []byte("v"), 0)
		}
	})
	sideB := zzv528RealDB(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		for i := 0; i < 40; i += 2 {
			zzv528Put(t, srv, "seed-"+strconv.Itoa(i), []byte("v"), 0)
		}
		for i := 1; i < 40; i += 2 {
			zzv528Put(t, srv, "new-"+strconv.Itoa(i), []byte("v"), 0)
		}
	})

	var reference []string
	for attempt := 0; attempt < 3; attempt++ {
		_, changes, err := zzv528Collect(t, CompareConfig{SnapshotAPath: sideA, SnapshotBPath: sideB})
		require.NoError(t, err)
		keys := zzv528Keys(changes)
		assert.True(t, sort.StringsAreSorted(keys), "keys must be reported in byte order")
		if reference == nil {
			reference = keys
			continue
		}
		assert.Equal(t, reference, keys, "the report order must be stable")
	}
	require.NotEmpty(t, reference)
}
