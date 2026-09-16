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
	"fmt"
	"os"
	"sort"
	"strings"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/server/v3/storage/mvcc"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

// Revision selection sentinel errors. Callers can match them with errors.Is
// to distinguish user-recoverable revision selection failures from snapshot
// corruption and I/O failures.
var (
	// ErrRevisionCompacted is returned when the requested revision is older
	// than the readable (finished) compaction revision of the snapshot.
	ErrRevisionCompacted = errors.New("requested revision has been compacted")
	// ErrRevisionInFuture is returned when the requested revision is newer
	// than the latest revision stored in the snapshot.
	ErrRevisionInFuture = errors.New("requested revision is a future revision")
)

// CompareConfig configures an offline comparison of two snapshot files.
type CompareConfig struct {
	// SnapshotAPath and SnapshotBPath are the two snapshot (or backend) files
	// to compare. Both files are opened strictly read-only.
	SnapshotAPath string
	SnapshotBPath string

	// RevisionA and RevisionB select the revisions at which each side is
	// read. A value of 0 means the latest readable revision of the snapshot.
	// The comparison reports how the keyspace changes from side A to side B:
	// keys present only in B are "added", keys present only in A are
	// "deleted".
	RevisionA int64
	RevisionB int64

	// RangeStart and RangeEnd restrict the comparison to the byte interval
	// [RangeStart, RangeEnd). A nil/empty RangeStart starts at the first key.
	// A nil RangeEnd or RangeEnd equal to []byte{0} means an open upper bound.
	RangeStart []byte
	RangeEnd   []byte
}

// SideRevisionInfo describes the revision actually used while reading one
// side of the comparison.
type SideRevisionInfo struct {
	// Path is the snapshot file of the side.
	Path string `json:"path"`
	// RequestedRevision is the revision requested by the caller; 0 means
	// that the latest revision was requested.
	RequestedRevision int64 `json:"requestedRevision"`
	// Revision is the revision at which the side was actually read.
	Revision int64 `json:"revision"`
	// LatestRevision is the newest readable revision stored in the snapshot.
	LatestRevision int64 `json:"latestRevision"`
	// CompactRevision is the finished compaction revision (-1 if the
	// snapshot has never been compacted). Revisions strictly smaller than
	// this value are no longer readable.
	CompactRevision int64 `json:"compactRevision"`
}

// KeyRange identifies the byte interval the comparison was restricted to.
// A null Start or End in the JSON output marks an open bound.
type KeyRange struct {
	Start []byte `json:"start"`
	End   []byte `json:"end"`
}

// KeyState is the logical state of one business key at the selected revision
// of one side. It contains only user-visible metadata; value bytes are
// reported alongside it by KeyChange.
type KeyState struct {
	Value          []byte `json:"value"`
	CreateRevision int64  `json:"createRevision"`
	ModRevision    int64  `json:"modRevision"`
	Version        int64  `json:"version"`
	// Lease is the ID of the lease bound to the key, 0 means no lease.
	Lease int64 `json:"lease"`
}

// ChangeType is the kind of difference reported for one business key.
type ChangeType string

const (
	// ChangeAdded means the key exists only on side B.
	ChangeAdded ChangeType = "added"
	// ChangeDeleted means the key exists only on side A.
	ChangeDeleted ChangeType = "deleted"
	// ChangeModified means the key exists on both sides but its value or
	// metadata differs.
	ChangeModified ChangeType = "modified"
)

// KeyChange describes a single key difference. Keys are reported in byte
// order. Before is nil for added keys and After is nil for deleted keys.
// For modified keys, the "*Changed" flags explain which logical fields
// differ: value bytes, create revision, mod revision, version or lease
// binding.
type KeyChange struct {
	Type   ChangeType `json:"type"`
	Key    []byte     `json:"key"`
	Before *KeyState  `json:"before,omitempty"`
	After  *KeyState  `json:"after,omitempty"`

	ValueChanged          bool `json:"valueChanged,omitempty"`
	CreateRevisionChanged bool `json:"createRevisionChanged,omitempty"`
	ModRevisionChanged    bool `json:"modRevisionChanged,omitempty"`
	VersionChanged        bool `json:"versionChanged,omitempty"`
	LeaseChanged          bool `json:"leaseChanged,omitempty"`
}

// CompareSummary is returned after a successful comparison and aggregates
// the report header and the per-change counters.
type CompareSummary struct {
	A SideRevisionInfo `json:"a"`
	B SideRevisionInfo `json:"b"`
	// Range is the byte interval the comparison was restricted to.
	Range KeyRange `json:"range"`
	// TotalKeysA and TotalKeysB are the numbers of live keys in range on
	// each side at the selected revisions.
	TotalKeysA int `json:"totalKeysA"`
	TotalKeysB int `json:"totalKeysB"`
	Added      int `json:"added"`
	Deleted    int `json:"deleted"`
	Modified   int `json:"modified"`
	// ValueChanged etc. count modified keys carrying each kind of attribute
	// change. One modified key may contribute to several counters.
	ValueChanged          int `json:"valueChanged"`
	CreateRevisionChanged int `json:"createRevisionChanged"`
	ModRevisionChanged    int `json:"modRevisionChanged"`
	VersionChanged        int `json:"versionChanged"`
	LeaseChanged          int `json:"leaseChanged"`
	// Equal reports whether the two sides hold identical logical keyspace
	// state in the selected range.
	Equal bool `json:"equal"`
}

// Compare reads two offline snapshots at the requested revisions and invokes
// visit for every business key difference, in key byte order. visit is
// called while the snapshots are open; retaining the KeyChange (or its byte
// slices) beyond the call is not supported. Comparison memory is bounded by
// the number of distinct keys metadata, not by the total value volume:
// values are fetched from the read-only memory mapped files one pair at a
// time and are never accumulated.
//
// Compare fails explicitly (and never reports a partial result) when a
// snapshot cannot be opened or fails integrity checks, when the requested
// revision has been compacted or is in the future, when ctx is cancelled,
// or when visit returns an error. Input files are never modified.
func Compare(ctx context.Context, cfg CompareConfig, visit func(KeyChange) error) (CompareSummary, error) {
	summary := CompareSummary{Range: KeyRange{Start: cfg.RangeStart, End: cfg.RangeEnd}}

	if strings.TrimSpace(cfg.SnapshotAPath) == "" || strings.TrimSpace(cfg.SnapshotBPath) == "" {
		return summary, errors.New("both snapshot paths must be provided")
	}
	if cfg.RevisionA < 0 || cfg.RevisionB < 0 {
		return summary, errors.New("revision must be non-negative, use 0 for latest revision")
	}
	if err := validateRange(cfg.RangeStart, cfg.RangeEnd); err != nil {
		return summary, err
	}

	dbA, err := openSnapshotReadOnly(cfg.SnapshotAPath)
	if err != nil {
		return summary, fmt.Errorf("open snapshot A %q: %w", cfg.SnapshotAPath, err)
	}
	defer dbA.Close()
	dbB, err := openSnapshotReadOnly(cfg.SnapshotBPath)
	if err != nil {
		return summary, fmt.Errorf("open snapshot B %q: %w", cfg.SnapshotBPath, err)
	}
	defer dbB.Close()

	// All reads happen inside nested read transactions so that value bytes
	// returned by the bbolt cursors stay valid (they point into the mmap).
	err = dbA.View(func(txA *bolt.Tx) error {
		sideA, err := prepareSide(ctx, txA, cfg.SnapshotAPath, cfg.RevisionA, cfg.RangeStart, cfg.RangeEnd)
		if err != nil {
			return err
		}
		summary.A = sideA.info
		summary.TotalKeysA = len(sideA.liveKeys)

		return dbB.View(func(txB *bolt.Tx) error {
			sideB, err := prepareSide(ctx, txB, cfg.SnapshotBPath, cfg.RevisionB, cfg.RangeStart, cfg.RangeEnd)
			if err != nil {
				return err
			}
			summary.B = sideB.info
			summary.TotalKeysB = len(sideB.liveKeys)

			if err := mergeSides(ctx, sideA, sideB, visit, &summary); err != nil {
				return err
			}
			summary.Equal = summary.Added == 0 && summary.Deleted == 0 && summary.Modified == 0
			return nil
		})
	})
	if err != nil {
		return CompareSummary{Range: summary.Range}, err
	}
	return summary, nil
}

// validateRange mirrors the etcd range semantics: an empty start and a nil,
// empty or single-zero end means the whole keyspace.
func validateRange(start, end []byte) error {
	if len(end) == 0 || bytes.Equal(end, []byte{0}) {
		return nil
	}
	if len(start) > 0 && bytes.Compare(start, end) >= 0 {
		return fmt.Errorf("invalid key range: start %q must be smaller than end %q", start, end)
	}
	return nil
}

// openSnapshotReadOnly opens the snapshot strictly for reading. It never
// creates the file and never takes a write lock, so snapshots in use by a
// running etcd remain untouched. A trailing sha256 digest appended by
// "etcdctl snapshot save" is tolerated the same way it is for "snapshot
// status".
func openSnapshotReadOnly(path string) (*bolt.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o400, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	return db, nil
}

// keyEntry is the compact per-key state retained while scanning a snapshot.
// It stores metadata only; values are fetched lazily during the merge.
type keyEntry struct {
	mod       mvcc.Revision
	tombstone bool

	create  int64
	version int64
	lease   int64
}

// sideState holds everything needed to read one snapshot during the merge.
type sideState struct {
	tx     *bolt.Tx
	cursor *bolt.Cursor

	info     SideRevisionInfo
	entries  map[string]*keyEntry
	liveKeys []string
}

// prepareSide validates the snapshot, resolves the requested revision and
// builds the range-filtered, metadata-only index of live keys.
func prepareSide(ctx context.Context, tx *bolt.Tx, path string, requestedRev int64, rangeStart, rangeEnd []byte) (*sideState, error) {
	if err := checkIntegrity(tx, path); err != nil {
		return nil, err
	}
	bucket := tx.Bucket(schema.Key.Name())
	if bucket == nil {
		return nil, fmt.Errorf("snapshot %q is corrupt: %q bucket not found", path, string(schema.Key.Name()))
	}

	finishedCompact := readFinishedCompact(tx)
	scheduledCompact, _ := readScheduledCompact(tx)

	// First pass: integrity of every revision record and latest revision.
	latestRev, err := scanLatestRevision(ctx, bucket, path)
	if err != nil {
		return nil, err
	}
	// Mirror mvcc.store.restore(): a scheduled compaction persisted right
	// before a crash may advance the logical current revision even when the
	// last physical key revision is a compacted tombstone.
	if scheduledCompact > latestRev {
		latestRev = scheduledCompact
	}
	if latestRev < finishedCompact && finishedCompact > 0 {
		latestRev = finishedCompact
	}
	if latestRev < 1 {
		latestRev = 1
	}

	resolvedRev := requestedRev
	if resolvedRev == 0 {
		resolvedRev = latestRev
	}
	if resolvedRev < finishedCompact {
		return nil, fmt.Errorf("snapshot %q: %w (requested=%d, compact=%d)", path, ErrRevisionCompacted, requestedRev, finishedCompact)
	}
	if resolvedRev > latestRev {
		return nil, fmt.Errorf("snapshot %q: %w (requested=%d, latest=%d)", path, ErrRevisionInFuture, requestedRev, latestRev)
	}

	entries := make(map[string]*keyEntry)
	if err := scanKeyspace(ctx, bucket, path, resolvedRev, rangeStart, rangeEnd, entries); err != nil {
		return nil, err
	}

	liveKeys := make([]string, 0, len(entries))
	for key, ent := range entries {
		if !ent.tombstone {
			liveKeys = append(liveKeys, key)
		}
	}
	sort.Strings(liveKeys)

	return &sideState{
		tx:       tx,
		cursor:   bucket.Cursor(),
		entries:  entries,
		liveKeys: liveKeys,
		info: SideRevisionInfo{
			Path:              path,
			RequestedRevision: requestedRev,
			Revision:          resolvedRev,
			LatestRevision:    latestRev,
			CompactRevision:   finishedCompact,
		},
	}, nil
}

func readFinishedCompact(tx *bolt.Tx) int64 {
	meta := tx.Bucket(schema.Meta.Name())
	if meta == nil {
		return -1
	}
	v := meta.Get(schema.FinishedCompactKeyName)
	if len(v) == 0 {
		return -1
	}
	rev, err := safeBytesToRev(v)
	if err != nil {
		return -1
	}
	return rev.Main
}

func readScheduledCompact(tx *bolt.Tx) (int64, bool) {
	meta := tx.Bucket(schema.Meta.Name())
	if meta == nil {
		return 0, false
	}
	v := meta.Get(schema.ScheduledCompactKeyName)
	if len(v) == 0 {
		return 0, false
	}
	rev, err := safeBytesToRev(v)
	if err != nil {
		return 0, false
	}
	return rev.Main, true
}

// checkIntegrity runs the bbolt structural check the same way "snapshot
// status" does and turns every reported problem into a hard failure.
func checkIntegrity(tx *bolt.Tx, path string) error {
	var dbErrStrings []string
	for dbErr := range tx.Check() {
		dbErrStrings = append(dbErrStrings, dbErr.Error())
	}
	if len(dbErrStrings) > 0 {
		return fmt.Errorf("snapshot %q integrity check failed, %d errors found:\n%s",
			path, len(dbErrStrings), strings.Join(dbErrStrings, "\n"))
	}
	return nil
}

// scanLatestRevision walks the key bucket once to determine the newest main
// revision. Malformed revision keys are reported as corruption.
func scanLatestRevision(ctx context.Context, bucket *bolt.Bucket, path string) (int64, error) {
	var latest int64
	c := bucket.Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		rev, _, err := safeParseBucketKey(k)
		if err != nil {
			return 0, fmt.Errorf("snapshot %q is corrupt: cannot parse revision key: %w", path, err)
		}
		if rev.Main > latest {
			latest = rev.Main
		}
	}
	return latest, nil
}

// scanKeyspace walks revision records in ascending revision order and keeps,
// per in-range user key, only the effective state at targetRev. Walking in
// revision order means repeated puts, deletes and recreations collapse into
// the correct final interpretation of the key at targetRev.
func scanKeyspace(ctx context.Context, bucket *bolt.Bucket, path string, targetRev int64, rangeStart, rangeEnd []byte, entries map[string]*keyEntry) error {
	c := bucket.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		rev, isTombstone, err := safeParseBucketKey(k)
		if err != nil {
			return fmt.Errorf("snapshot %q is corrupt: cannot parse revision key: %w", path, err)
		}
		// Records are revision ordered, so every remaining record is newer
		// than the requested revision.
		if rev.Main > targetRev {
			break
		}
		kv := &mvccpb.KeyValue{}
		if err := proto.Unmarshal(v, kv); err != nil {
			return fmt.Errorf("snapshot %q is corrupt: cannot unmarshal key value at revision %d: %w", path, rev.Main, err)
		}
		if !keyInRange(kv.Key, rangeStart, rangeEnd) {
			continue
		}
		ent := &keyEntry{mod: rev, tombstone: isTombstone}
		if !isTombstone {
			ent.create = kv.CreateRevision
			ent.version = kv.Version
			ent.lease = kv.Lease
		}
		// Overwriting on equal main revisions relies on ascending sub
		// revisions: the last sub of a transaction is the effective one.
		entries[string(kv.Key)] = ent
	}
	return nil
}

func keyInRange(key, start, end []byte) bool {
	if len(start) > 0 && bytes.Compare(key, start) < 0 {
		return false
	}
	if len(end) > 0 && !bytes.Equal(end, []byte{0}) && bytes.Compare(key, end) >= 0 {
		return false
	}
	return true
}

// mergeSides walks both sides' sorted live keys and reports differences.
// Values are fetched from the mmap through the cursors only for keys that
// actually differ, one pair at a time.
func mergeSides(ctx context.Context, a, b *sideState, visit func(KeyChange) error, summary *CompareSummary) error {
	i, j := 0, 0
	for i < len(a.liveKeys) || j < len(b.liveKeys) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var key string
		var cmp int
		switch {
		case i >= len(a.liveKeys):
			key = b.liveKeys[j]
			cmp = 1
		case j >= len(b.liveKeys):
			key = a.liveKeys[i]
			cmp = -1
		default:
			cmp = strings.Compare(a.liveKeys[i], b.liveKeys[j])
			if cmp <= 0 {
				key = a.liveKeys[i]
			} else {
				key = b.liveKeys[j]
			}
		}

		var change *KeyChange
		var err error
		switch cmp {
		case -1:
			change, err = buildDeletedChange(a, key)
			i++
		case 1:
			change, err = buildAddedChange(b, key)
			j++
		default:
			change, err = buildModifiedChange(a, b, key)
			i++
			j++
		}
		if err != nil {
			return err
		}
		if change == nil {
			continue
		}

		switch change.Type {
		case ChangeAdded:
			summary.Added++
		case ChangeDeleted:
			summary.Deleted++
		case ChangeModified:
			summary.Modified++
			if change.ValueChanged {
				summary.ValueChanged++
			}
			if change.CreateRevisionChanged {
				summary.CreateRevisionChanged++
			}
			if change.ModRevisionChanged {
				summary.ModRevisionChanged++
			}
			if change.VersionChanged {
				summary.VersionChanged++
			}
			if change.LeaseChanged {
				summary.LeaseChanged++
			}
		}
		if err := visit(*change); err != nil {
			return err
		}
	}
	return nil
}

func buildAddedChange(side *sideState, key string) (*KeyChange, error) {
	ent := side.entries[key]
	state, err := loadKeyState(side, key, ent)
	if err != nil {
		return nil, err
	}
	return &KeyChange{Type: ChangeAdded, Key: []byte(key), After: state}, nil
}

func buildDeletedChange(side *sideState, key string) (*KeyChange, error) {
	ent := side.entries[key]
	state, err := loadKeyState(side, key, ent)
	if err != nil {
		return nil, err
	}
	return &KeyChange{Type: ChangeDeleted, Key: []byte(key), Before: state}, nil
}

func buildModifiedChange(a, b *sideState, key string) (*KeyChange, error) {
	entA := a.entries[key]
	entB := b.entries[key]
	stateA, err := loadKeyState(a, key, entA)
	if err != nil {
		return nil, err
	}
	stateB, err := loadKeyState(b, key, entB)
	if err != nil {
		return nil, err
	}

	change := &KeyChange{
		Type:   ChangeModified,
		Key:    []byte(key),
		Before: stateA,
		After:  stateB,
	}
	change.ValueChanged = !bytes.Equal(stateA.Value, stateB.Value)
	change.CreateRevisionChanged = entA.create != entB.create
	change.ModRevisionChanged = entA.mod.Main != entB.mod.Main || entA.mod.Sub != entB.mod.Sub
	change.VersionChanged = entA.version != entB.version
	change.LeaseChanged = entA.lease != entB.lease

	if !change.ValueChanged && !change.CreateRevisionChanged && !change.ModRevisionChanged &&
		!change.VersionChanged && !change.LeaseChanged {
		return nil, nil
	}
	return change, nil
}

// loadKeyState materializes one key's logical state, fetching its value from
// the memory mapped snapshot through an exact revision cursor seek.
func loadKeyState(side *sideState, key string, ent *keyEntry) (*KeyState, error) {
	revBytes := mvcc.NewRevBytes()
	revBytes = mvcc.RevToBytes(ent.mod, revBytes)

	gotKey, valBytes := side.cursor.Seek(revBytes)
	if !bytes.Equal(gotKey, revBytes) {
		return nil, fmt.Errorf("snapshot %q is corrupt: value for key %q at revision %d not found",
			side.info.Path, key, ent.mod.Main)
	}
	kv := &mvccpb.KeyValue{}
	if err := proto.Unmarshal(valBytes, kv); err != nil {
		return nil, fmt.Errorf("snapshot %q is corrupt: cannot unmarshal value for key %q: %w", side.info.Path, key, err)
	}
	return &KeyState{
		Value:          kv.Value,
		CreateRevision: ent.create,
		ModRevision:    ent.mod.Main,
		Version:        ent.version,
		Lease:          ent.lease,
	}, nil
}

// safeBytesToRev parses 17-byte revision bytes without panicking.
func safeBytesToRev(b []byte) (mvcc.Revision, error) {
	rev, _, err := safeParseBucketKey(b)
	return rev, err
}

// On-disk revision key lengths, see mvcc.revision.go:
// 8 bytes main revision + 1 byte '_' separator + 8 bytes sub revision,
// plus 1 trailing tombstone marker for delete records.
const (
	revBytesLen       = 17
	markedRevBytesLen = 18
)

// safeParseBucketKey validates and parses bucket revision bytes. It turns
// the panics of mvcc.BytesToBucketKey into ordinary corruption errors and
// reports whether the record is a tombstone.
func safeParseBucketKey(b []byte) (rev mvcc.Revision, tombstone bool, err error) {
	if len(b) != revBytesLen && len(b) != markedRevBytesLen {
		return mvcc.Revision{}, false, fmt.Errorf("invalid revision key length: %d", len(b))
	}
	if b[8] != '_' {
		return mvcc.Revision{}, false, fmt.Errorf("invalid revision key separator at position 8: %q", b[8])
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	bk := mvcc.BytesToBucketKey(b)
	return bk.Revision, mvcc.IsTombstone(b), nil
}
