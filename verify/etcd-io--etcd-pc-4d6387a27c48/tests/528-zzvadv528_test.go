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

// Adversarial acceptance checks for precheck 528.
//
// The comparison must fail explicitly on a snapshot it cannot interpret. A
// snapshot whose key bucket contains only unreadable revision records is
// damaged data, and the requirement says such input "应明确失败，不能发布看似
// 完整的比较结果".

package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"go.etcd.io/etcd/server/v3/storage/schema"
)

func zzvAdvEmptyDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "damaged.db")
	db, err := bolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(schema.Key.Name()); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(schema.Meta.Name())
		return err
	}))
	require.NoError(t, db.Close())
	return path
}

// TestZZVAdv528UnreadableKeyRecordsMustNotCompareEqual checks that a snapshot
// whose key bucket holds only damaging records is reported as corrupt instead of
// being compared as an empty keyspace.
func TestZZVAdv528UnreadableKeyRecordsMustNotCompareEqual(t *testing.T) {
	healthy := zzvAdvEmptyDB(t)
	damaged := zzvAdvEmptyDB(t)

	db, err := bolt.Open(damaged, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(schema.Key.Name())
		// A 17-byte record whose separator byte is wrong: the revision cannot be
		// decoded and the protobuf payload is meaningless.
		bad := make([]byte, 17)
		for i := range bad {
			bad[i] = 0x00
		}
		bad[8] = 'x'
		if err := bucket.Put(bad, []byte{0xff, 0xff}); err != nil {
			return err
		}
		short := []byte{0x01}
		return bucket.Put(short, []byte{0xff})
	}))
	require.NoError(t, db.Close())

	reported := 0
	_, err = Compare(context.Background(), CompareConfig{
		SnapshotAPath: damaged, SnapshotBPath: healthy,
	}, func(KeyChange) error { reported++; return nil })

	if err == nil {
		t.Fatalf("comparing a snapshot whose key records are unreadable succeeded "+
			"(reported %d changes); damaged input must fail explicitly", reported)
	}
	t.Logf("comparison correctly refused the damaged snapshot: %v", err)
}

// TestZZVAdv528SameFileIsEqualDespiteDifferentBackends checks the positive
// control for the case above: a healthy snapshot compared with itself is equal.
func TestZZVAdv528SameFileIsEqualDespiteDifferentBackends(t *testing.T) {
	healthy := zzvAdvEmptyDB(t)
	summary, err := Compare(context.Background(), CompareConfig{
		SnapshotAPath: healthy, SnapshotBPath: healthy,
	}, func(KeyChange) error { return nil })
	require.NoError(t, err)
	assert.True(t, summary.Equal)
}

// TestZZVAdv528FileMissingTheKeyBucketMustFail checks the empty-bucket case.
func TestZZVAdv528FileMissingTheKeyBucketMustFail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-key-bucket.db")
	db, err := bolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(schema.Meta.Name())
		return err
	}))
	require.NoError(t, db.Close())

	_, err = Compare(context.Background(), CompareConfig{
		SnapshotAPath: path, SnapshotBPath: path,
	}, func(KeyChange) error { return nil })
	require.Error(t, err, "a snapshot without the key bucket must not compare as empty")
	assert.Contains(t, err.Error(), "bucket")
}

var _ = os.Stat
