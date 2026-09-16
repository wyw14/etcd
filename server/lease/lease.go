// Copyright 2022 The etcd Authors
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
	"math"
	"sort"
	"sync"
	"time"

	"go.etcd.io/etcd/server/v3/lease/leasepb"
	"go.etcd.io/etcd/server/v3/storage/backend"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

type Lease struct {
	ID           LeaseID
	ttl          int64 // time to live of the lease in seconds
	remainingTTL int64 // remaining time to live in seconds, if zero valued it is considered unset and the full ttl should be used
	// expiryMu protects concurrent accesses to expiry
	expiryMu sync.RWMutex
	// expiry is time when lease should expire. no expiration when expiry.IsZero() is true
	expiry time.Time

	// mu protects concurrent accesses to itemSet and bindingVersion
	mu      sync.RWMutex
	itemSet map[LeaseItem]struct{}
	// bindingVersion is bumped every time the attached item set changes, i.e.
	// when a new item is attached or an attached item is detached. Re-attaching
	// an item that is already attached (e.g. rewriting the value of a key that
	// is already bound to the lease) and lease renewals do not bump it. It is
	// used to invalidate protected-revoke credentials; detaching a key and
	// later re-attaching it bumps the version twice, even if the resulting
	// item set is identical.
	bindingVersion uint64
	// instance uniquely identifies one granted lease instance. A lease granted
	// after a previous lease with the same ID was revoked gets a different
	// instance. The value is assigned deterministically (in raft apply order)
	// so all cluster members make the same protected-revoke decision.
	instance uint64
	// revoking is set by ProtectedRevoke once the credential has been accepted,
	// freezing the lease against new bindings for the duration of the deletion.
	// It is guarded by the lessor mutex.
	revoking bool
	revokec  chan struct{}
}

func NewLease(id LeaseID, ttl int64) *Lease {
	return &Lease{
		ID:      id,
		ttl:     ttl,
		itemSet: make(map[LeaseItem]struct{}),
		revokec: make(chan struct{}),
	}
}

func (l *Lease) expired() bool {
	return l.Remaining() <= 0
}

func (l *Lease) persistTo(b backend.Backend) {
	lpb := leasepb.Lease{ID: int64(l.ID), TTL: l.ttl, RemainingTTL: l.remainingTTL}
	tx := b.BatchTx()
	tx.LockInsideApply()
	defer tx.Unlock()
	schema.MustUnsafePutLease(tx, &lpb)
}

// TTL returns the TTL of the Lease.
func (l *Lease) TTL() int64 {
	return l.ttl
}

// SetLeaseItem sets the given lease item, this func is thread-safe
func (l *Lease) SetLeaseItem(item LeaseItem) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.itemSet[item] = struct{}{}
}

// getRemainingTTL returns the last checkpointed remaining TTL of the lease.
func (l *Lease) getRemainingTTL() int64 {
	if l.remainingTTL > 0 {
		return l.remainingTTL
	}
	return l.ttl
}

// refresh refreshes the expiry of the lease.
func (l *Lease) refresh(extend time.Duration) {
	newExpiry := time.Now().Add(extend + time.Duration(l.getRemainingTTL())*time.Second)
	l.expiryMu.Lock()
	defer l.expiryMu.Unlock()
	l.expiry = newExpiry
}

// forever sets the expiry of lease to be forever.
func (l *Lease) forever() {
	l.expiryMu.Lock()
	defer l.expiryMu.Unlock()
	l.expiry = forever
}

// Demoted returns true if the lease's expiry has been reset to forever.
func (l *Lease) Demoted() bool {
	l.expiryMu.RLock()
	defer l.expiryMu.RUnlock()
	return l.expiry == forever
}

// Keys returns all the keys attached to the lease.
func (l *Lease) Keys() []string {
	l.mu.RLock()
	keys := make([]string, 0, len(l.itemSet))
	for k := range l.itemSet {
		keys = append(keys, k.Key)
	}
	l.mu.RUnlock()
	return keys
}

// attachItemsLocked adds the given items to the lease's binding set. It returns
// true when at least one item was not attached before, i.e. when the binding
// relationship changed. bindingVersion is bumped exactly once in that case, so
// re-attaching an already attached item (e.g. rewriting the value of a bound
// key) does not invalidate protected-revoke credentials.
// The caller must hold l.mu.
func (l *Lease) attachItemsLocked(items []LeaseItem) (changed bool) {
	for _, it := range items {
		if _, ok := l.itemSet[it]; !ok {
			l.itemSet[it] = struct{}{}
			changed = true
		}
	}
	if changed {
		l.bindingVersion++
	}
	return changed
}

// detachItemsLocked removes the given items from the lease's binding set. It
// returns true when at least one item was attached before. Detaching a key and
// re-attaching it later bumps the binding version twice, even if the resulting
// binding set is identical to the original.
// The caller must hold l.mu.
func (l *Lease) detachItemsLocked(items []LeaseItem) (changed bool) {
	for _, it := range items {
		if _, ok := l.itemSet[it]; ok {
			delete(l.itemSet, it)
			changed = true
		}
	}
	if changed {
		l.bindingVersion++
	}
	return changed
}

// bindingSnapshot returns a sorted copy of the keys attached to the lease and
// the current binding version. The two values are read together so callers can
// trust that the returned keys correspond to the returned version.
func (l *Lease) bindingSnapshot() (keys []string, bindingVersion uint64) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	keys = make([]string, 0, len(l.itemSet))
	for k := range l.itemSet {
		keys = append(keys, k.Key)
	}
	sort.Strings(keys)
	return keys, l.bindingVersion
}

// Instance returns the opaque identity of this granted lease instance. It is
// immutable for the lifetime of the Lease object.
func (l *Lease) Instance() uint64 {
	return l.instance
}

// BindingVersion returns the current version of the lease's binding set. The
// version is bumped on every actual attach/detach change.
func (l *Lease) BindingVersion() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.bindingVersion
}

// Remaining returns the remaining time of the lease.
func (l *Lease) Remaining() time.Duration {
	l.expiryMu.RLock()
	defer l.expiryMu.RUnlock()
	if l.expiry.IsZero() {
		return time.Duration(math.MaxInt64)
	}
	return time.Until(l.expiry)
}

type LeaseItem struct {
	Key string
}

// leasesByExpiry implements the sort.Interface.
type leasesByExpiry []*Lease

func (le leasesByExpiry) Len() int           { return len(le) }
func (le leasesByExpiry) Less(i, j int) bool { return le[i].Remaining() < le[j].Remaining() }
func (le leasesByExpiry) Swap(i, j int)      { le[i], le[j] = le[j], le[i] }
