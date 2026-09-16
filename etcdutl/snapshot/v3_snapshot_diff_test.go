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

package snapshot

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/server/v3/storage/mvcc"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

// tombstoneRevBytes builds an 18-byte tombstone revision key the same way
// mvcc encodes delete records (17-byte revision + 't' marker).
func tombstoneRevBytes(main, sub int64) []byte {
	b := mvcc.RevToBytes(mvcc.Revision{Main: main, Sub: sub}, mvcc.NewRevBytes())
	return append(b, mvccTombstoneMark)
}

const mvccTombstoneMark = byte('t')

// testSnapshot is a handcrafted bbolt file following the etcd key/meta
// bucket on-disk layout.
type testSnapshot struct {
	t    *testing.T
	path string
	db   *bolt.DB
}

func newTestSnapshot(t *testing.T) *testSnapshot {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := bolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(schema.Key.Name())
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(schema.Meta.Name())
		return err
	}))
	return &testSnapshot{t: t, path: path, db: db}
}

func (s *testSnapshot) put(main, sub int64, kv *mvccpb.KeyValue) {
	s.t.Helper()
	keyBytes := mvcc.RevToBytes(mvcc.Revision{Main: main, Sub: sub}, mvcc.NewRevBytes())
	valBytes, err := proto.Marshal(kv)
	require.NoError(s.t, err)
	require.NoError(s.t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(schema.Key.Name()).Put(keyBytes, valBytes)
	}))
}

func (s *testSnapshot) delete(main, sub int64, key []byte) {
	s.t.Helper()
	valBytes, err := proto.Marshal(&mvccpb.KeyValue{Key: key})
	require.NoError(s.t, err)
	require.NoError(s.t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(schema.Key.Name()).Put(tombstoneRevBytes(main, sub), valBytes)
	}))
}

func (s *testSnapshot) setFinishedCompact(rev int64) {
	s.t.Helper()
	val := mvcc.RevToBytes(mvcc.Revision{Main: rev}, mvcc.NewRevBytes())
	require.NoError(s.t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(schema.Meta.Name()).Put(schema.FinishedCompactKeyName, val)
	}))
}

func (s *testSnapshot) putRawKey(key, val []byte) {
	s.t.Helper()
	require.NoError(s.t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(schema.Key.Name()).Put(key, val)
	}))
}

func (s *testSnapshot) close() {
	require.NoError(s.t, s.db.Close())
}

func putKV(main int64, key, value []byte, create, version, lease int64) *mvccpb.KeyValue {
	return &mvccpb.KeyValue{
		Key:            key,
		Value:          value,
		CreateRevision: create,
		ModRevision:    main,
		Version:        version,
		Lease:          lease,
	}
}

func collectChanges(t *testing.T, cfg CompareConfig) (CompareSummary, []KeyChange) {
	t.Helper()
	var changes []KeyChange
	summary, err := Compare(context.Background(), cfg, func(change KeyChange) error {
		// The contract forbids retaining mmap-backed slices, so deep-copy for
		// test assertions.
		copied := KeyChange{
			Type:                  change.Type,
			Key:                   append([]byte(nil), change.Key...),
			Before:                copyState(change.Before),
			After:                 copyState(change.After),
			ValueChanged:          change.ValueChanged,
			CreateRevisionChanged: change.CreateRevisionChanged,
			ModRevisionChanged:    change.ModRevisionChanged,
			VersionChanged:        change.VersionChanged,
			LeaseChanged:          change.LeaseChanged,
		}
		changes = append(changes, copied)
		return nil
	})
	require.NoError(t, err)
	return summary, changes
}

func copyState(s *KeyState) *KeyState {
	if s == nil {
		return nil
	}
	return &KeyState{
		Value:          append([]byte(nil), s.Value...),
		CreateRevision: s.CreateRevision,
		ModRevision:    s.ModRevision,
		Version:        s.Version,
		Lease:          s.Lease,
	}
}

func buildSnapshotA(t *testing.T) *testSnapshot {
	s := newTestSnapshot(t)
	s.put(2, 0, putKV(2, []byte("alpha"), []byte("one"), 2, 1, 0))
	s.put(3, 0, putKV(3, []byte("beta"), []byte("two"), 3, 1, 0))
	s.put(4, 0, putKV(4, []byte("gamma"), []byte("g"), 4, 1, 42))
	s.put(7, 0, putKV(7, []byte("old"), []byte("oldv"), 7, 1, 0))
	return s
}

func buildSnapshotB(t *testing.T) *testSnapshot {
	s := newTestSnapshot(t)
	s.put(2, 0, putKV(2, []byte("alpha"), []byte("one"), 2, 1, 0))
	s.put(3, 0, putKV(3, []byte("beta"), []byte("two"), 3, 1, 0))
	s.put(5, 0, putKV(5, []byte("beta"), []byte("TWO"), 3, 2, 0))
	s.put(4, 0, putKV(4, []byte("gamma"), []byte("g"), 4, 1, 42))
	s.put(6, 0, putKV(6, []byte("gamma"), []byte("g"), 4, 2, 0))
	s.put(8, 0, putKV(8, []byte("delta"), []byte("d"), 8, 1, 0))
	s.delete(9, 0, []byte("old"))
	return s
}

func TestCompareAddedDeletedModified(t *testing.T) {
	a, b := buildSnapshotA(t), buildSnapshotB(t)
	a.close()
	b.close()

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path})

	require.Len(t, changes, 4)
	// Key byte order: beta < delta < gamma < old.
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, []byte("beta"), changes[0].Key)
	assert.True(t, changes[0].ValueChanged)
	assert.True(t, changes[0].ModRevisionChanged)
	assert.True(t, changes[0].VersionChanged)
	assert.False(t, changes[0].CreateRevisionChanged)
	assert.False(t, changes[0].LeaseChanged)
	assert.Equal(t, []byte("two"), changes[0].Before.Value)
	assert.Equal(t, []byte("TWO"), changes[0].After.Value)
	assert.Equal(t, int64(3), changes[0].Before.ModRevision)
	assert.Equal(t, int64(5), changes[0].After.ModRevision)

	assert.Equal(t, ChangeAdded, changes[1].Type)
	assert.Equal(t, []byte("delta"), changes[1].Key)
	assert.Nil(t, changes[1].Before)
	assert.Equal(t, []byte("d"), changes[1].After.Value)

	assert.Equal(t, ChangeModified, changes[2].Type)
	assert.Equal(t, []byte("gamma"), changes[2].Key)
	assert.False(t, changes[2].ValueChanged)
	assert.True(t, changes[2].LeaseChanged)
	assert.True(t, changes[2].ModRevisionChanged)
	assert.True(t, changes[2].VersionChanged)
	assert.False(t, changes[2].CreateRevisionChanged)
	assert.Equal(t, int64(42), changes[2].Before.Lease)
	assert.Equal(t, int64(0), changes[2].After.Lease)

	assert.Equal(t, ChangeDeleted, changes[3].Type)
	assert.Equal(t, []byte("old"), changes[3].Key)
	assert.Nil(t, changes[3].After)
	assert.Equal(t, []byte("oldv"), changes[3].Before.Value)

	assert.Equal(t, 1, summary.Added)
	assert.Equal(t, 1, summary.Deleted)
	assert.Equal(t, 2, summary.Modified)
	assert.Equal(t, 1, summary.ValueChanged)
	assert.Equal(t, 0, summary.CreateRevisionChanged)
	assert.Equal(t, 2, summary.ModRevisionChanged)
	assert.Equal(t, 2, summary.VersionChanged)
	assert.Equal(t, 1, summary.LeaseChanged)
	assert.False(t, summary.Equal)
	assert.Equal(t, 4, summary.TotalKeysA)
	assert.Equal(t, 4, summary.TotalKeysB)
	assert.Equal(t, int64(7), summary.A.LatestRevision)
	assert.Equal(t, int64(9), summary.B.LatestRevision)
	assert.Equal(t, int64(0), summary.A.RequestedRevision)
	assert.Equal(t, int64(7), summary.A.Revision)
	assert.Equal(t, int64(-1), summary.A.CompactRevision)
}

func TestCompareEqualSnapshots(t *testing.T) {
	a, b := buildSnapshotA(t), buildSnapshotA(t)
	a.close()
	b.close()

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path})
	assert.Empty(t, changes)
	assert.True(t, summary.Equal)
	assert.Equal(t, 4, summary.TotalKeysA)
	assert.Equal(t, 4, summary.TotalKeysB)
}

func TestCompareEmptySnapshots(t *testing.T) {
	a, b := newTestSnapshot(t), newTestSnapshot(t)
	a.close()
	b.close()

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path})
	assert.Empty(t, changes)
	assert.True(t, summary.Equal)
	assert.Equal(t, int64(1), summary.A.Revision)
}

// buildHistorySnapshot contains multiple updates, a delete and a recreate of
// the same key, plus two puts of another key within one transaction (sub
// revisions).
func buildHistorySnapshot(t *testing.T) *testSnapshot {
	s := newTestSnapshot(t)
	s.put(1, 0, putKV(1, []byte("k"), []byte("v1"), 1, 1, 0))
	s.put(2, 0, putKV(2, []byte("k"), []byte("v2"), 1, 2, 0))
	s.put(5, 0, putKV(5, []byte("k"), []byte("v3"), 1, 3, 0))
	s.delete(8, 0, []byte("k"))
	s.put(10, 0, putKV(10, []byte("k"), []byte("v4"), 10, 1, 0))
	s.put(12, 0, putKV(12, []byte("multi"), []byte("m1"), 12, 1, 0))
	s.put(12, 1, putKV(12, []byte("multi"), []byte("m2"), 12, 2, 0))
	return s
}

func TestCompareHistoricalRevisionAndRecreate(t *testing.T) {
	s := buildHistorySnapshot(t)
	s.close()

	t.Run("state at rev 6 shows v3", func(t *testing.T) {
		summary, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: s.path, RevisionA: 6,
			SnapshotBPath: s.path, RevisionB: 12,
		})
		require.False(t, summary.Equal)
		require.Len(t, changes, 2)
		assert.Equal(t, ChangeModified, changes[0].Type)
		assert.Equal(t, []byte("k"), changes[0].Key)
		assert.Equal(t, []byte("v3"), changes[0].Before.Value)
		assert.Equal(t, []byte("v4"), changes[0].After.Value)
		assert.Equal(t, int64(1), changes[0].Before.CreateRevision)
		assert.Equal(t, int64(10), changes[0].After.CreateRevision)
		assert.Equal(t, int64(5), changes[0].Before.ModRevision)
		assert.Equal(t, int64(10), changes[0].After.ModRevision)
		assert.Equal(t, int64(3), changes[0].Before.Version)
		assert.Equal(t, int64(1), changes[0].After.Version)

		assert.Equal(t, ChangeAdded, changes[1].Type)
		assert.Equal(t, []byte("multi"), changes[1].Key)
		assert.Equal(t, []byte("m2"), changes[1].After.Value)
		assert.Equal(t, int64(12), changes[1].After.ModRevision)
	})

	t.Run("state at rev 9 treats recreate at 10 as added", func(t *testing.T) {
		_, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: s.path, RevisionA: 9,
			SnapshotBPath: s.path, RevisionB: 12,
		})
		require.Len(t, changes, 2)
		assert.Equal(t, ChangeAdded, changes[0].Type)
		assert.Equal(t, []byte("k"), changes[0].Key)
		assert.Equal(t, ChangeAdded, changes[1].Type)
	})

	t.Run("last sub revision wins within a transaction", func(t *testing.T) {
		// Both sides at rev 8: k is deleted at 8, multi does not exist yet.
		_, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: s.path, RevisionA: 12,
			SnapshotBPath: s.path, RevisionB: 12,
		})
		assert.Empty(t, changes)
	})

	t.Run("same main revision selected exactly", func(t *testing.T) {
		_, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: s.path, RevisionA: 1,
			SnapshotBPath: s.path, RevisionB: 2,
		})
		require.Len(t, changes, 1)
		assert.Equal(t, []byte("v1"), changes[0].Before.Value)
		assert.Equal(t, []byte("v2"), changes[0].After.Value)
	})
}

func TestCompareRevisionSelectionErrors(t *testing.T) {
	s := buildHistorySnapshot(t)
	s.setFinishedCompact(8)
	s.close()

	cases := []struct {
		name    string
		revA    int64
		revB    int64
		wantErr error
	}{
		{"A compacted", 7, 12, ErrRevisionCompacted},
		{"B compacted", 12, 7, ErrRevisionCompacted},
		{"A future", 13, 12, ErrRevisionInFuture},
		{"B future", 12, 100, ErrRevisionInFuture},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			_, err := Compare(context.Background(), CompareConfig{
				SnapshotAPath: s.path, RevisionA: tc.revA,
				SnapshotBPath: s.path, RevisionB: tc.revB,
			}, func(KeyChange) error {
				called = true
				return nil
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.False(t, called, "no changes may be reported on failure")
		})
	}

	t.Run("revision exactly at compact boundary is readable", func(t *testing.T) {
		// rev 8 is the delete revision: k is absent at 8, multi absent.
		summary, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: s.path, RevisionA: 8,
			SnapshotBPath: s.path, RevisionB: 12,
		})
		assert.Equal(t, int64(8), summary.A.Revision)
		assert.Equal(t, int64(8), summary.A.CompactRevision)
		require.Len(t, changes, 2)
	})

	t.Run("negative revision rejected", func(t *testing.T) {
		_, err := Compare(context.Background(), CompareConfig{
			SnapshotAPath: s.path, RevisionA: -1,
			SnapshotBPath: s.path,
		}, nil)
		require.Error(t, err)
	})
}

func TestCompareKeyRange(t *testing.T) {
	b := buildSnapshotB(t)
	b.close()

	t.Run("start inclusive end exclusive", func(t *testing.T) {
		summary, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: b.path, SnapshotBPath: b.path,
			RangeStart: []byte("beta"), RangeEnd: []byte("gamma"),
		})
		assert.True(t, summary.Equal)
		assert.Equal(t, 2, summary.TotalKeysA) // beta, delta
		assert.Empty(t, changes)
	})

	t.Run("open upper bound with single zero byte", func(t *testing.T) {
		summary, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: b.path, SnapshotBPath: b.path,
			RangeStart: []byte("gamma"), RangeEnd: []byte{0},
		})
		assert.True(t, summary.Equal)
		// "old" was deleted, so only gamma remains at or after "gamma".
		assert.Equal(t, 1, summary.TotalKeysA)
		assert.Empty(t, changes)
	})

	t.Run("invalid range", func(t *testing.T) {
		_, err := Compare(context.Background(), CompareConfig{
			SnapshotAPath: b.path, SnapshotBPath: b.path,
			RangeStart: []byte("z"), RangeEnd: []byte("a"),
		}, nil)
		require.Error(t, err)
	})

	t.Run("nil and empty bounds mean the whole keyspace", func(t *testing.T) {
		summary, changes := collectChanges(t, CompareConfig{
			SnapshotAPath: b.path, SnapshotBPath: b.path,
			RangeStart: []byte(""), RangeEnd: []byte(""),
		})
		assert.True(t, summary.Equal)
		assert.Equal(t, 4, summary.TotalKeysA)
		assert.Empty(t, changes)
	})
}

func TestCompareBinaryKeysAndValues(t *testing.T) {
	a := newTestSnapshot(t)
	a.put(1, 0, putKV(1, []byte("utf8"), []byte("café"), 1, 1, 0))
	a.close()
	b := newTestSnapshot(t)
	b.put(1, 0, putKV(1, []byte("utf8"), []byte("café"), 1, 1, 0))
	binaryKey := []byte{0x00, 0xff, 0x01, 0x00}
	binaryValue := []byte{0x00, 0xff, 0x74, 0x0a, 't', 0x80}
	b.put(2, 0, putKV(2, binaryKey, binaryValue, 2, 1, 0))
	b.close()

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path})
	assert.False(t, summary.Equal)
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.True(t, bytes.Equal(binaryKey, changes[0].Key))
	assert.True(t, bytes.Equal(binaryValue, changes[0].After.Value))
}

// Logical state must be independent of file page layout, free pages and
// historical compaction differences.
func TestCompareIgnoresPhysicalLayoutAndHistory(t *testing.T) {
	x := newTestSnapshot(t)
	x.put(1, 0, putKV(1, []byte("k1"), []byte("v1"), 1, 1, 0))
	x.put(2, 0, putKV(2, []byte("k1"), []byte("v2"), 1, 2, 0))
	x.put(3, 0, putKV(3, []byte("k1"), []byte("v3"), 1, 3, 0))
	// junk that was created and deleted, plus different surviving history:
	x.put(4, 0, putKV(4, []byte("junk"), []byte("x"), 4, 1, 0))
	x.delete(5, 0, []byte("junk"))
	x.close()

	y := newTestSnapshot(t)
	// Compacted snapshot: only the boundary revision at 3 survived physically,
	// finished compaction is at 5.
	y.put(3, 0, putKV(3, []byte("k1"), []byte("v3"), 1, 3, 0))
	y.put(1, 0, putKV(1, []byte("zzz"), []byte("z1"), 1, 1, 0))
	y.delete(2, 0, []byte("zzz"))
	y.setFinishedCompact(5)
	y.close()

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: x.path, SnapshotBPath: y.path})
	assert.Empty(t, changes)
	assert.True(t, summary.Equal)
	assert.Equal(t, int64(-1), summary.A.CompactRevision)
	assert.Equal(t, int64(5), summary.B.CompactRevision)
	assert.Equal(t, int64(5), summary.B.Revision)
}

func TestCompareCorruptionFailures(t *testing.T) {
	t.Run("garbage file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "garbage.db")
		require.NoError(t, os.WriteFile(path, []byte("this is not a bolt database"), 0o600))
		good := buildSnapshotA(t)
		good.close()
		_, err := Compare(context.Background(), CompareConfig{SnapshotAPath: path, SnapshotBPath: good.path}, nil)
		require.Error(t, err)
	})

	t.Run("missing file", func(t *testing.T) {
		good := buildSnapshotA(t)
		good.close()
		_, err := Compare(context.Background(), CompareConfig{
			SnapshotAPath: filepath.Join(t.TempDir(), "missing.db"),
			SnapshotBPath: good.path,
		}, nil)
		require.Error(t, err)
	})

	t.Run("malformed revision key", func(t *testing.T) {
		s := buildSnapshotA(t)
		s.putRawKey([]byte("short"), []byte("x"))
		s.close()
		good := buildSnapshotA(t)
		good.close()
		_, err := Compare(context.Background(), CompareConfig{SnapshotAPath: s.path, SnapshotBPath: good.path}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "corrupt")
	})

	t.Run("malformed key value proto", func(t *testing.T) {
		s := buildSnapshotA(t)
		keyBytes := mvcc.RevToBytes(mvcc.Revision{Main: 6}, mvcc.NewRevBytes())
		s.putRawKey(keyBytes, []byte("not-a-protobuf"))
		s.close()
		good := buildSnapshotA(t)
		good.close()
		_, err := Compare(context.Background(), CompareConfig{SnapshotAPath: s.path, SnapshotBPath: good.path}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "corrupt")
	})

	t.Run("missing key bucket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.db")
		db, err := bolt.Open(path, 0o600, nil)
		require.NoError(t, err)
		require.NoError(t, db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket(schema.Meta.Name())
			return err
		}))
		require.NoError(t, db.Close())
		good := buildSnapshotA(t)
		good.close()
		_, err = Compare(context.Background(), CompareConfig{SnapshotAPath: path, SnapshotBPath: good.path}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "corrupt")
	})
}

func TestCompareInputsAreReadOnly(t *testing.T) {
	a, b := buildSnapshotA(t), buildSnapshotB(t)
	infoA, err := os.Stat(a.path)
	require.NoError(t, err)
	a.close()
	b.close()

	// Write-protect both files; a read-only open must still succeed and any
	// write attempt would fail.
	require.NoError(t, os.Chmod(a.path, 0o444))
	require.NoError(t, os.Chmod(b.path, 0o444))
	t.Cleanup(func() { _ = os.Chmod(a.path, 0o666); _ = os.Chmod(b.path, 0o666) })

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path})
	require.False(t, summary.Equal)
	assert.Len(t, changes, 4)

	// File metadata must be unchanged.
	afterA, err := os.Stat(a.path)
	require.NoError(t, err)
	assert.Equal(t, infoA.Size(), afterA.Size())
	assert.True(t, afterA.ModTime().Equal(infoA.ModTime()), "input file modification time changed")
}

func TestCompareToleratesTrailingSnapshotHash(t *testing.T) {
	s := buildSnapshotA(t)
	s.close()
	dir := t.TempDir()
	hashed := filepath.Join(dir, "snapshot-with-hash.db")
	raw, err := os.ReadFile(s.path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hashed, append(raw, make([]byte, 32)...), 0o600))

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: s.path, SnapshotBPath: hashed})
	assert.True(t, summary.Equal)
	assert.Empty(t, changes)
}

func TestCompareCancellationAndVisitorErrors(t *testing.T) {
	a, b := buildSnapshotA(t), buildSnapshotB(t)
	a.close()
	b.close()

	t.Run("pre-cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		called := 0
		_, err := Compare(ctx, CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path}, func(KeyChange) error {
			called++
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, called)
	})

	t.Run("visitor error aborts", func(t *testing.T) {
		visitorErr := errors.New("stop now")
		_, err := Compare(context.Background(), CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path}, func(KeyChange) error {
			return visitorErr
		})
		require.ErrorIs(t, err, visitorErr)
	})
}

// TestCompareMemoryBoundedByKeysNotValues ensures value payloads are streamed
// from the mmap and never retained: the live heap must not grow with the
// total value volume of the snapshots.
func TestCompareMemoryBoundedByKeysNotValues(t *testing.T) {
	if testing.Short() {
		t.Skip("memory bound test")
	}
	const (
		numKeys     = 120
		valueLength = 1024 * 1024 // 1 MiB; total value payload ~120 MiB per side
	)
	a, b := newTestSnapshot(t), newTestSnapshot(t)
	for i := range numKeys {
		main := int64(i + 1)
		key := []byte("key-" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + "-padding-key-name")
		value := bytes.Repeat([]byte{byte(i)}, valueLength)
		a.put(main, 0, putKV(main, key, value, main, 1, 0))
		b.put(main, 0, putKV(main, key, value, main, 1, 0))
	}
	a.close()
	b.close()

	runtime.GC()
	debug.FreeOSMemory()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	summary, changes := collectChanges(t, CompareConfig{SnapshotAPath: a.path, SnapshotBPath: b.path})
	require.True(t, summary.Equal)
	require.Empty(t, changes)

	runtime.GC()
	debug.FreeOSMemory()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	// Retaining just one side's values would require ~120 MiB; allow a wide
	// margin for runtime and test allocations.
	assert.Less(t, growth, int64(80*1024*1024),
		"heap grew %d bytes comparing %d keys of %d-byte values; values must not be retained", growth, numKeys, valueLength)
}
