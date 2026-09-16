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

// ProtectedRevokeToken is the credential returned together with a protected
// revoke preview. The caller must present it unchanged to ProtectedRevoke.
//
// The token binds together:
//   - LeaseID: the lease the preview was taken for;
//   - Instance: the exact granted lease instance, so a token cannot be replayed
//     against a different lease granted with the same ID after revocation;
//   - BindingVersion: the version of the lease's attached-key set at preview
//     time, so any attach/detach (even a detach followed by a re-attach that
//     restores the same key set) invalidates the token.
//
// Both Instance and BindingVersion advance only as a result of raft-applied
// operations (Grant/Attach/Detach), so every member evaluating the token makes
// the same decision as long as it applied the same raft prefix. When protected
// revoke is exposed over raft, the binding version (and instance) must be
// included in the replicated lease state, so members catching up through a
// snapshot reconstruct the exact values the credential was issued against.
//
// A token is pure state: no preview record is kept server-side, so revoking or
// expiring a lease leaves no lingering preview state. Tokens do not authorize
// anything by themselves; callers must still enforce lease-revoke permissions
// when issuing the preview and when carrying out the revoke.
type ProtectedRevokeToken struct {
	LeaseID        LeaseID
	Instance       uint64
	BindingVersion uint64
}

// ProtectedRevokePreview is returned by PreviewProtectedRevoke. It contains the
// lease identity, the keys currently bound to the lease (sorted), and the
// credential that must be presented to revoke the lease protectedly. Only the
// keys listed here can be deleted by a successful ProtectedRevoke using Token.
type ProtectedRevokePreview struct {
	LeaseID LeaseID
	// Instance identifies the exact granted lease instance the preview belongs to.
	Instance uint64
	// Keys is a sorted snapshot of the keys attached to the lease at preview time.
	Keys []string
	// Token is the credential to present to ProtectedRevoke.
	Token ProtectedRevokeToken
}
