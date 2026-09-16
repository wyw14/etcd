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

package etcdutl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/etcdutl/v3/snapshot"
	"go.etcd.io/etcd/pkg/v3/cobrautl"
	"go.etcd.io/etcd/server/v3/storage/mvcc"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

type diffTestRec struct {
	main      int64
	sub       int64
	tombstone bool
	kv        *mvccpb.KeyValue
}

func createDiffTestDB(t *testing.T, name string, recs []diffTestRec, finishedCompact int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	db, err := bolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(schema.Key.Name()); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(schema.Meta.Name())
		return err
	}))
	for _, rec := range recs {
		require.NoError(t, db.Update(func(tx *bolt.Tx) error {
			var keyBytes []byte
			rev := mvcc.Revision{Main: rec.main, Sub: rec.sub}
			if rec.tombstone {
				keyBytes = append(mvcc.RevToBytes(rev, mvcc.NewRevBytes()), byte('t'))
			} else {
				keyBytes = mvcc.RevToBytes(rev, mvcc.NewRevBytes())
			}
			val, err := proto.Marshal(rec.kv)
			if err != nil {
				return err
			}
			return tx.Bucket(schema.Key.Name()).Put(keyBytes, val)
		}))
	}
	if finishedCompact > 0 {
		require.NoError(t, db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(schema.Meta.Name()).Put(
				schema.FinishedCompactKeyName,
				mvcc.RevToBytes(mvcc.Revision{Main: finishedCompact}, mvcc.NewRevBytes()))
		}))
	}
	require.NoError(t, db.Close())
	return path
}

func diffKV(main int64, key, value []byte, create, version, lease int64) *mvccpb.KeyValue {
	return &mvccpb.KeyValue{
		Key:            key,
		Value:          value,
		CreateRevision: create,
		ModRevision:    main,
		Version:        version,
		Lease:          lease,
	}
}

func buildDiffTestDBs(t *testing.T) (string, string) {
	t.Helper()
	a := createDiffTestDB(t, "a.db", []diffTestRec{
		{main: 1, kv: diffKV(1, []byte("k1"), []byte("v1"), 1, 1, 0)},
		{main: 2, kv: diffKV(2, []byte("k2"), []byte("v2"), 2, 1, 0)},
	}, 0)
	b := createDiffTestDB(t, "b.db", []diffTestRec{
		{main: 1, kv: diffKV(1, []byte("k1"), []byte("v1"), 1, 1, 0)},
		{main: 5, kv: diffKV(5, []byte("k2"), []byte("v2-new"), 2, 2, 0)},
		{main: 6, kv: diffKV(6, []byte("k3"), []byte{0x00, 0xff, 'x'}, 6, 1, 77)},
	}, 0)
	return a, b
}

type jsonDiffReport struct {
	Status string `json:"status"`
	A      struct {
		Path              string `json:"path"`
		RequestedRevision int64  `json:"requestedRevision"`
		Revision          int64  `json:"revision"`
		LatestRevision    int64  `json:"latestRevision"`
		CompactRevision   int64  `json:"compactRevision"`
	} `json:"a"`
	B struct {
		Revision        int64 `json:"revision"`
		CompactRevision int64 `json:"compactRevision"`
	} `json:"b"`
	Range struct {
		Start *string `json:"start"`
		End   *string `json:"end"`
	} `json:"range"`
	Changes []struct {
		Type   string `json:"type"`
		Key    string `json:"key"`
		Before *struct {
			Value          string `json:"value"`
			CreateRevision int64  `json:"createRevision"`
			ModRevision    int64  `json:"modRevision"`
			Version        int64  `json:"version"`
			Lease          int64  `json:"lease"`
		} `json:"before"`
		After *struct {
			Value          string `json:"value"`
			CreateRevision int64  `json:"createRevision"`
			ModRevision    int64  `json:"modRevision"`
			Version        int64  `json:"version"`
			Lease          int64  `json:"lease"`
		} `json:"after"`
		ValueChanged          bool `json:"valueChanged"`
		CreateRevisionChanged bool `json:"createRevisionChanged"`
		ModRevisionChanged    bool `json:"modRevisionChanged"`
		VersionChanged        bool `json:"versionChanged"`
		LeaseChanged          bool `json:"leaseChanged"`
	} `json:"changes"`
	Summary struct {
		TotalKeysA int  `json:"totalKeysA"`
		TotalKeysB int  `json:"totalKeysB"`
		Added      int  `json:"added"`
		Deleted    int  `json:"deleted"`
		Modified   int  `json:"modified"`
		Equal      bool `json:"equal"`
	} `json:"summary"`
}

func TestRunSnapshotDiffJSONToFile(t *testing.T) {
	a, b := buildDiffTestDBs(t)
	output := filepath.Join(t.TempDir(), "report.json")

	err := runSnapshotDiff(context.Background(), a, b, snapshotDiffOptions{outputPath: output}, diffFormatJSON)
	require.NoError(t, err)

	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	var report jsonDiffReport
	require.NoError(t, json.Unmarshal(raw, &report), "published JSON must be complete and parseable: %s", string(raw))

	assert.Equal(t, "complete", report.Status)
	assert.Equal(t, a, report.A.Path)
	assert.Equal(t, int64(0), report.A.RequestedRevision)
	assert.Equal(t, int64(2), report.A.Revision)
	assert.Equal(t, int64(2), report.A.LatestRevision)
	assert.Equal(t, int64(6), report.B.Revision)
	assert.Equal(t, int64(-1), report.A.CompactRevision)
	assert.Nil(t, report.Range.Start)
	assert.Nil(t, report.Range.End)

	require.Len(t, report.Changes, 2)
	// Key byte order: k2 < k3.
	assert.Equal(t, "modified", report.Changes[0].Type)
	key2, err := base64.StdEncoding.DecodeString(report.Changes[0].Key)
	require.NoError(t, err)
	assert.Equal(t, []byte("k2"), key2)
	assert.True(t, report.Changes[0].ValueChanged)
	assert.True(t, report.Changes[0].ModRevisionChanged)
	assert.True(t, report.Changes[0].VersionChanged)
	assert.Equal(t, "v2", mustB64(t, report.Changes[0].Before.Value))
	assert.Equal(t, "v2-new", mustB64(t, report.Changes[0].After.Value))

	assert.Equal(t, "added", report.Changes[1].Type)
	key3, err := base64.StdEncoding.DecodeString(report.Changes[1].Key)
	require.NoError(t, err)
	assert.Equal(t, []byte("k3"), key3)
	// Binary values are encoded losslessly as base64.
	val3, err := base64.StdEncoding.DecodeString(report.Changes[1].After.Value)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0xff, 'x'}, val3)
	assert.Equal(t, int64(77), report.Changes[1].After.Lease)

	assert.Equal(t, 1, report.Summary.Added)
	assert.Equal(t, 0, report.Summary.Deleted)
	assert.Equal(t, 1, report.Summary.Modified)
	assert.False(t, report.Summary.Equal)
	assert.Equal(t, 2, report.Summary.TotalKeysA)
	assert.Equal(t, 3, report.Summary.TotalKeysB)
}

func TestRunSnapshotDiffSimpleToFile(t *testing.T) {
	a, b := buildDiffTestDBs(t)
	output := filepath.Join(t.TempDir(), "report.txt")

	err := runSnapshotDiff(context.Background(), a, b, snapshotDiffOptions{outputPath: output}, diffFormatSimple)
	require.NoError(t, err)

	content, err := os.ReadFile(output)
	require.NoError(t, err)
	text := string(content)
	assert.Contains(t, text, "Snapshot diff (A => B)")
	assert.Contains(t, text, "requested_revision=latest revision=2 latest_revision=2 compact_revision=-1")
	assert.Contains(t, text, "Range: start=(beginning) end=(open)")
	assert.Contains(t, text, "MODIFIED key=\"k2\"")
	assert.Contains(t, text, "value: \"v2\" => \"v2-new\"")
	assert.Contains(t, text, "ADDED    key=\"k3\"")
	assert.Contains(t, text, "Summary: added=1 deleted=0 modified=1")
	assert.Contains(t, text, "Result: DIFFERENT")
}

func TestRunSnapshotDiffEqual(t *testing.T) {
	a, _ := buildDiffTestDBs(t)
	// Build a second snapshot logically identical to A.
	equal := createDiffTestDB(t, "equal.db", []diffTestRec{
		{main: 1, kv: diffKV(1, []byte("k1"), []byte("v1"), 1, 1, 0)},
		{main: 2, kv: diffKV(2, []byte("k2"), []byte("v2"), 2, 1, 0)},
	}, 0)

	output := filepath.Join(t.TempDir(), "equal.json")
	require.NoError(t, runSnapshotDiff(context.Background(), a, equal, snapshotDiffOptions{outputPath: output}, diffFormatJSON))
	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	var report jsonDiffReport
	require.NoError(t, json.Unmarshal(raw, &report))
	assert.True(t, report.Summary.Equal)
	assert.Empty(t, report.Changes)
}

func TestRunSnapshotDiffRangeFlags(t *testing.T) {
	a, b := buildDiffTestDBs(t)
	output := filepath.Join(t.TempDir(), "range.json")

	err := runSnapshotDiff(context.Background(), a, b, snapshotDiffOptions{
		outputPath: output,
		rangeStart: []byte("k3"),
		rangeEnd:   []byte{0x00},
	}, diffFormatJSON)
	require.NoError(t, err)

	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	var report jsonDiffReport
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Changes, 1)
	assert.Equal(t, "added", report.Changes[0].Type)
	require.NotNil(t, report.Range.Start)
	require.NotNil(t, report.Range.End)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("k3")), *report.Range.Start)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte{0x00}), *report.Range.End)
}

func TestRunSnapshotDiffFailuresPublishNothing(t *testing.T) {
	_, good := buildDiffTestDBs(t)
	garbage := filepath.Join(t.TempDir(), "garbage.db")
	require.NoError(t, os.WriteFile(garbage, []byte("not a database"), 0o600))

	t.Run("corrupt input", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "out.json")
		err := runSnapshotDiff(context.Background(), garbage, good, snapshotDiffOptions{outputPath: output}, diffFormatJSON)
		require.Error(t, err)
		_, statErr := os.Stat(output)
		assert.ErrorIs(t, statErr, os.ErrNotExist, "no partial report may be published")
	})

	t.Run("compacted revision", func(t *testing.T) {
		compacted := createDiffTestDB(t, "compact.db", []diffTestRec{
			{main: 10, kv: diffKV(10, []byte("k"), []byte("v"), 10, 1, 0)},
		}, 10)
		output := filepath.Join(t.TempDir(), "out.json")
		err := runSnapshotDiff(context.Background(), compacted, good, snapshotDiffOptions{
			outputPath: output, revisionA: 3,
		}, diffFormatJSON)
		require.Error(t, err)
		assert.ErrorIs(t, err, snapshot.ErrRevisionCompacted)
		_, statErr := os.Stat(output)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		output := filepath.Join(t.TempDir(), "out.json")
		err := runSnapshotDiff(ctx, good, good, snapshotDiffOptions{outputPath: output}, diffFormatJSON)
		require.ErrorIs(t, err, context.Canceled)
		_, statErr := os.Stat(output)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("output directory missing", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "missing-dir", "out.json")
		err := runSnapshotDiff(context.Background(), good, good, snapshotDiffOptions{outputPath: output}, diffFormatJSON)
		require.Error(t, err)
		assert.ErrorIs(t, err, errDiffOutput)
	})

	t.Run("unsupported format", func(t *testing.T) {
		err := runSnapshotDiff(context.Background(), good, good, snapshotDiffOptions{
			outputPath: filepath.Join(t.TempDir(), "out.bin"),
		}, "protobuf")
		require.Error(t, err)
	})
}

func TestRunSnapshotDiffLargeValueJSONAssembly(t *testing.T) {
	// A single change record much larger than the 64 KiB replay buffer must
	// still produce one complete, parseable JSON document.
	large := bytes.Repeat([]byte("abcdef0123456789"), 10000) // 160 KiB
	a := createDiffTestDB(t, "a.db", []diffTestRec{
		{main: 1, kv: diffKV(1, []byte("big"), []byte("small"), 1, 1, 0)},
	}, 0)
	b := createDiffTestDB(t, "b.db", []diffTestRec{
		{main: 1, kv: diffKV(1, []byte("big"), large, 1, 1, 0)},
	}, 0)
	output := filepath.Join(t.TempDir(), "large.json")
	require.NoError(t, runSnapshotDiff(context.Background(), a, b, snapshotDiffOptions{outputPath: output}, diffFormatJSON))

	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	var report jsonDiffReport
	require.NoError(t, json.Unmarshal(raw, &report), "large report must be complete JSON")
	require.Len(t, report.Changes, 1)
	assert.Equal(t, "modified", report.Changes[0].Type)
	assert.True(t, report.Changes[0].ValueChanged)
	val, err := base64.StdEncoding.DecodeString(report.Changes[0].After.Value)
	require.NoError(t, err)
	assert.Equal(t, large, val)
	assert.Equal(t, "complete", report.Status)
}

func TestDiffExitCode(t *testing.T) {
	assert.Equal(t, cobrautl.ExitInterrupted, diffExitCode(context.Canceled))
	assert.Equal(t, cobrautl.ExitIO, diffExitCode(errDiffOutput))
	assert.Equal(t, cobrautl.ExitBadArgs, diffExitCode(snapshot.ErrRevisionCompacted))
	assert.Equal(t, cobrautl.ExitBadArgs, diffExitCode(snapshot.ErrRevisionInFuture))
	assert.Equal(t, cobrautl.ExitError, diffExitCode(errors.New("corrupt")))
}

func TestSnapshotDiffCommandRegistered(t *testing.T) {
	cmd := NewSnapshotCommand()
	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Use == "diff <filename-a> <filename-b>" {
			found = true
			for _, flag := range []string{"rev-a", "rev-b", "range-start", "range-end", "output"} {
				assert.NotNil(t, sub.Flags().Lookup(flag), "missing flag %q", flag)
			}
		}
	}
	assert.True(t, found, "diff subcommand must be registered")
}

func mustB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return string(b)
}
