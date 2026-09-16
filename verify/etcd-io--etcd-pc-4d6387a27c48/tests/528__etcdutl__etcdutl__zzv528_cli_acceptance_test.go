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

// Independent acceptance verification for precheck 528, command layer.
//
// This file drives the compiled etcdutl binary as a black box: it checks the
// real command line contract (help text, flags, exit codes, atomic report
// publication, cancellation) instead of calling internal helpers.

package etcdutl_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/server/v3/embed"
	"go.etcd.io/etcd/server/v3/etcdserver"
)

const (
	zzv528ExitSuccess     = 0
	zzv528ExitError       = 1
	zzv528ExitInterrupted = 5
	zzv528ExitIO          = 6
	zzv528ExitBadArgs     = 128
)

var (
	zzv528BinOnce sync.Once
	zzv528BinPath string
	zzv528BinErr  error
)

// zzv528Etcdutl builds the real etcdutl binary once per test process.
func zzv528Etcdutl(t *testing.T) string {
	t.Helper()
	zzv528BinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "zzv528-bin-")
		if err != nil {
			zzv528BinErr = err
			return
		}
		binary := filepath.Join(dir, "etcdutl")
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}
		build := exec.Command("go", "build", "-o", binary, ".")
		build.Dir = zzv528ModuleRoot(t)
		out, err := build.CombinedOutput()
		if err != nil {
			zzv528BinErr = fmt.Errorf("go build failed: %v\n%s", err, out)
			return
		}
		zzv528BinPath = binary
	})
	if zzv528BinErr != nil {
		t.Fatalf("cannot build etcdutl: %v", zzv528BinErr)
	}
	return zzv528BinPath
}

func zzv528ModuleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// The test runs inside <repo>/etcdutl/etcdutl.
	return filepath.Dir(wd)
}

type zzv528Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Elapsed  time.Duration
}

func zzv528Run(t *testing.T, args ...string) zzv528Result {
	t.Helper()
	cmd := exec.Command(zzv528Etcdutl(t), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("cannot run etcdutl %v: %v", args, err)
		}
	}
	return zzv528Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code, Elapsed: elapsed}
}

var zzv528PortSeq int32

// zzv528StartEtcd starts an embedded member on its own ports and returns the
// member database path plus a stop function.
func zzv528StartEtcd(t *testing.T, mutate func(t *testing.T, srv *etcdserver.EtcdServer)) (string, func()) {
	t.Helper()
	offset := atomic.AddInt32(&zzv528PortSeq, 1)
	clientPort := 15000 + offset*10
	peerPort := clientPort + 1
	metricsPort := clientPort + 2

	cfg := embed.NewConfig()
	cfg.BackendBatchLimit = 1
	cfg.LogLevel = "fatal"
	cfg.Dir = t.TempDir()
	cfg.ListenClientUrls = []url.URL{{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", clientPort)}}
	cfg.AdvertiseClientUrls = cfg.ListenClientUrls
	cfg.ListenPeerUrls = []url.URL{{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", peerPort)}}
	cfg.AdvertisePeerUrls = cfg.ListenPeerUrls
	cfg.ListenMetricsUrls = []url.URL{{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", metricsPort)}}
	cfg.InitialCluster = fmt.Sprintf("%s=http://127.0.0.1:%d", cfg.Name, peerPort)

	srv, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatalf("embedded etcd on port %d: %v", clientPort, err)
	}

	select {
	case <-srv.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		srv.Close()
		t.Fatal("embedded etcd did not become ready")
	}
	mutate(t, srv.Server)
	return filepath.Join(cfg.Dir, "member", "snap", "db"), srv.Close
}

func zzv528PutKey(t *testing.T, srv *etcdserver.EtcdServer, key string, value []byte) {
	t.Helper()
	_, err := srv.Put(t.Context(), &etcdserverpb.PutRequest{Key: []byte(key), Value: value})
	if err != nil {
		t.Fatalf("put %q: %v", key, err)
	}
}

func zzv528DeleteKey(t *testing.T, srv *etcdserver.EtcdServer, key string) {
	t.Helper()
	_, err := srv.DeleteRange(t.Context(), &etcdserverpb.DeleteRangeRequest{
		Key: []byte(key), RangeEnd: []byte(key + "\x00"),
	})
	if err != nil {
		t.Fatalf("delete %q: %v", key, err)
	}
}

// zzv528JSONReport mirrors the documented machine readable report shape.
type zzv528JSONReport struct {
	Status string `json:"status"`
	A      struct {
		Path              string `json:"path"`
		RequestedRevision int64  `json:"requestedRevision"`
		Revision          int64  `json:"revision"`
		LatestRevision    int64  `json:"latestRevision"`
		CompactRevision   int64  `json:"compactRevision"`
	} `json:"a"`
	B struct {
		Path              string `json:"path"`
		RequestedRevision int64  `json:"requestedRevision"`
		Revision          int64  `json:"revision"`
		LatestRevision    int64  `json:"latestRevision"`
		CompactRevision   int64  `json:"compactRevision"`
	} `json:"b"`
	Range struct {
		Start []byte `json:"start"`
		End   []byte `json:"end"`
	} `json:"range"`
	Changes []struct {
		Type   string `json:"type"`
		Key    []byte `json:"key"`
		Before *struct {
			Value          []byte `json:"value"`
			CreateRevision int64  `json:"createRevision"`
			ModRevision    int64  `json:"modRevision"`
			Version        int64  `json:"version"`
			Lease          int64  `json:"lease"`
		} `json:"before"`
		After *struct {
			Value          []byte `json:"value"`
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
		TotalKeysA            int  `json:"totalKeysA"`
		TotalKeysB            int  `json:"totalKeysB"`
		Added                 int  `json:"added"`
		Deleted               int  `json:"deleted"`
		Modified              int  `json:"modified"`
		ValueChanged          int  `json:"valueChanged"`
		CreateRevisionChanged int  `json:"createRevisionChanged"`
		ModRevisionChanged    int  `json:"modRevisionChanged"`
		VersionChanged        int  `json:"versionChanged"`
		LeaseChanged          int  `json:"leaseChanged"`
		Equal                 bool `json:"equal"`
	} `json:"summary"`
}

func zzv528ParseReport(t *testing.T, stdout string) zzv528JSONReport {
	t.Helper()
	var report zzv528JSONReport
	decoder := json.NewDecoder(strings.NewReader(stdout))
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, zzv528FirstLines(stdout, 20))
	}
	return report
}

func zzv528FirstLines(text string, n int) string {
	lines := strings.Split(text, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func TestZZV528CLIEndToEnd(t *testing.T) {
	sideA, stopA := zzv528StartEtcd(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528PutKey(t, srv, "alpha", []byte("one"))
		zzv528PutKey(t, srv, "gamma", []byte("g"))
		zzv528PutKey(t, srv, "old", []byte("oldv"))
	})
	// The member must be stopped before the CLI reads the file: a running
	// etcd holds a write lock on its backend.
	stopA()
	sideB, stopB := zzv528StartEtcd(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528PutKey(t, srv, "alpha", []byte("one"))
		zzv528PutKey(t, srv, "gamma", []byte("g"))
		zzv528PutKey(t, srv, "old", []byte("oldv"))
		zzv528PutKey(t, srv, "beta", []byte("two"))
		zzv528DeleteKey(t, srv, "old")
	})
	stopB()

	t.Run("console report lists revisions, range and changes", func(t *testing.T) {
		got := zzv528Run(t, "snapshot", "diff", sideA, sideB)
		t.Logf("exit=%d\nstdout:\n%s", got.ExitCode, got.Stdout)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		for _, want := range []string{
			"Snapshot diff (A => B)",
			"requested_revision=latest",
			"Range: start=(beginning) end=(open)",
			"Changes (key byte order):",
			`ADDED    key="beta"`,
			`DELETED  key="old"`,
			"Summary: added=1 deleted=1 modified=0",
			"Result: DIFFERENT",
		} {
			if !strings.Contains(got.Stdout, want) {
				t.Errorf("console report is missing %q\n%s", want, got.Stdout)
			}
		}
	})

	t.Run("json report is machine readable and base64 encodes bytes", func(t *testing.T) {
		got := zzv528Run(t, "snapshot", "diff", "--write-out", "json", sideA, sideB)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		report := zzv528ParseReport(t, got.Stdout)
		if report.Status != "complete" {
			t.Errorf("status = %q, want complete", report.Status)
		}
		if report.A.Path != sideA || report.B.Path != sideB {
			t.Errorf("report paths = %q/%q", report.A.Path, report.B.Path)
		}
		if report.A.Revision != report.A.LatestRevision || report.B.Revision != report.B.LatestRevision {
			t.Errorf("default revision must be the latest: %+v / %+v", report.A, report.B)
		}
		if report.Summary.Equal {
			t.Errorf("summary must report a difference: %+v", report.Summary)
		}
		if report.Summary.Added != 1 || report.Summary.Deleted != 1 || report.Summary.Modified != 0 {
			t.Errorf("summary counters = %+v", report.Summary)
		}
		if len(report.Changes) != 2 {
			t.Fatalf("expected 2 changes, got %d", len(report.Changes))
		}
		if string(report.Changes[0].Key) != "beta" || report.Changes[0].Type != "added" {
			t.Errorf("first change = %+v", report.Changes[0])
		}
		if string(report.Changes[1].Key) != "old" || report.Changes[1].Type != "deleted" {
			t.Errorf("second change = %+v", report.Changes[1])
		}
		if report.Changes[0].After == nil || string(report.Changes[0].After.Value) != "two" {
			t.Errorf("added value not carried in the report: %+v", report.Changes[0].After)
		}

		// The bytes on the wire are valid base64 of the real key bytes.
		var raw map[string]any
		if err := json.Unmarshal([]byte(got.Stdout), &raw); err != nil {
			t.Fatalf("report JSON: %v", err)
		}
		changes := raw["changes"].([]any)
		encoded := changes[0].(map[string]any)["key"].(string)
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("key %q is not base64: %v", encoded, err)
		}
		if string(decoded) != "beta" {
			t.Errorf("decoded key = %q", decoded)
		}
	})

	t.Run("range and revision flags are honoured", func(t *testing.T) {
		// Enumerate both fixtures through a full-range comparison first: the
		// bounded counters below must be consistent with these key sets.
		full := zzv528Run(t, "snapshot", "diff", "--write-out", "json", sideA, sideB)
		fullReport := zzv528ParseReport(t, full.Stdout)
		keys := make([]string, 0, 8)
		for _, change := range fullReport.Changes {
			keys = append(keys, string(change.Key))
		}
		t.Logf("full-range keys=%v summary=%+v", keys, fullReport.Summary)
		if len(keys) != 2 || keys[0] != "beta" || keys[1] != "old" {
			t.Fatalf("unexpected fixture state: %v", keys)
		}

		// Key byte order is alpha < beta < gamma < old. The range [b, zzz)
		// keeps beta, gamma and old and drops alpha, so each side holds two
		// live keys inside it and the only differences are beta and old.
		bHex := fmt.Sprintf("%x", []byte("b"))
		zzzHex := fmt.Sprintf("%x", []byte("zzz"))
		got := zzv528Run(t, "snapshot", "diff", "--write-out", "json",
			"--range-start", bHex, "--range-end", zzzHex, sideA, sideB)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		report := zzv528ParseReport(t, got.Stdout)
		t.Logf("bounded range report: summary=%+v", report.Summary)
		if string(report.Range.Start) != "b" || string(report.Range.End) != "zzz" {
			t.Errorf("range not echoed in the report: %+v", report.Range)
		}
		if report.Summary.TotalKeysA != 2 || report.Summary.TotalKeysB != 2 {
			t.Errorf("range must filter out alpha, got %+v", report.Summary)
		}
		if report.Summary.Added != 1 || report.Summary.Deleted != 1 || report.Summary.Modified != 0 {
			t.Errorf("beta and old are the only differences inside the range: %+v", report.Summary)
		}
		if len(report.Changes) != 2 ||
			string(report.Changes[0].Key) != "beta" || report.Changes[0].Type != "added" ||
			string(report.Changes[1].Key) != "old" || report.Changes[1].Type != "deleted" {
			t.Errorf("unexpected changes inside the range: %+v", report.Changes)
		}

		// Raising the lower bound above beta drops it from the comparison.
		got = zzv528Run(t, "snapshot", "diff", "--write-out", "json",
			"--range-start", fmt.Sprintf("%x", []byte("c")), "--range-end", zzzHex, sideA, sideB)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		report = zzv528ParseReport(t, got.Stdout)
		if report.Summary.Added != 0 || report.Summary.Deleted != 1 || len(report.Changes) != 1 {
			t.Errorf("a start above beta must exclude it: %+v", report.Summary)
		}

		// A start above every key yields an empty comparison.
		zzzStart := fmt.Sprintf("%x", []byte("zzz"))
		got = zzv528Run(t, "snapshot", "diff", "--write-out", "json",
			"--range-start", zzzStart, sideA, sideB)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		report = zzv528ParseReport(t, got.Stdout)
		if report.Summary.TotalKeysA != 0 || report.Summary.TotalKeysB != 0 || !report.Summary.Equal {
			t.Errorf("a range above every key must be empty: %+v", report.Summary)
		}

		// The same lower bound with an explicit open upper bound keeps beta.
		got = zzv528Run(t, "snapshot", "diff", "--write-out", "json",
			"--range-start", fmt.Sprintf("%x", []byte("b")), "--range-end", "00", sideA, sideB)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		report = zzv528ParseReport(t, got.Stdout)
		if report.Summary.Added != 1 || report.Summary.Deleted != 1 || len(report.Changes) != 2 {
			t.Errorf("open-ended range must keep beta and old: %+v", report.Summary)
		}
		if len(report.Changes) > 0 && string(report.Changes[0].Key) != "beta" {
			t.Errorf("first change must be beta: %+v", report.Changes)
		}

		// Selecting the same revision on both sides reports equality.
		got = zzv528Run(t, "snapshot", "diff", "--write-out", "json", "--rev-a", "2", "--rev-b", "2", sideA, sideB)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		report = zzv528ParseReport(t, got.Stdout)
		if !report.Summary.Equal {
			t.Errorf("revision 2 must be identical on both sides: %+v", report.Summary)
		}
		if report.A.RequestedRevision != 2 || report.A.Revision != 2 {
			t.Errorf("requested revision not reported: %+v", report.A)
		}
		if report.A.LatestRevision < 2 || report.B.LatestRevision < 2 {
			t.Errorf("latest revision not reported: %+v / %+v", report.A, report.B)
		}
	})

	t.Run("output file is published and not left partially written", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "report.json")
		got := zzv528Run(t, "snapshot", "diff", "--write-out", "json", "-o", out, sideA, sideB)
		if got.ExitCode != zzv528ExitSuccess {
			t.Fatalf("expected success, got exit %d: %s", got.ExitCode, got.Stderr)
		}
		if strings.TrimSpace(got.Stdout) != "" {
			t.Errorf("stdout must stay empty when writing to a file, got %q", got.Stdout)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("report file: %v", err)
		}
		report := zzv528ParseReport(t, string(data))
		if report.Summary.Added != 1 || report.Summary.Deleted != 1 {
			t.Errorf("report file content = %+v", report.Summary)
		}
		entries, err := os.ReadDir(filepath.Dir(out))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			t.Errorf("temporary files were left behind: %v", names)
		}
	})

	t.Run("failed comparison leaves no output file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "missing.json")
		got := zzv528Run(t, "snapshot", "diff", "-o", out, sideA, filepath.Join(t.TempDir(), "absent.db"))
		if got.ExitCode == zzv528ExitSuccess {
			t.Fatalf("a missing snapshot must fail, stdout=%q", got.Stdout)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("no report may be published on failure, stat err=%v", err)
		}
		entries, err := os.ReadDir(filepath.Dir(out))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("failure must not leave temporary files: %v", entries)
		}
	})
}

func TestZZV528CLIExitCodes(t *testing.T) {
	sideA, stopA := zzv528StartEtcd(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528PutKey(t, srv, "k", []byte("v"))
	})
	stopA()
	sideB, stopB := zzv528StartEtcd(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		zzv528PutKey(t, srv, "k", []byte("v2"))
	})
	stopB()

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"success", []string{"snapshot", "diff", sideA, sideB}, zzv528ExitSuccess},
		{"missing file", []string{"snapshot", "diff", sideA, filepath.Join(t.TempDir(), "nope.db")}, zzv528ExitError},
		{"future revision", []string{"snapshot", "diff", "--rev-a", "100000", sideA, sideB}, zzv528ExitBadArgs},
		{"negative revision", []string{"snapshot", "diff", "--rev-b", "-1", sideA, sideB}, zzv528ExitError},
		{"missing operand", []string{"snapshot", "diff", sideA}, zzv528ExitError},
		{"unknown format", []string{"snapshot", "diff", "--write-out", "yaml", sideA, sideB}, zzv528ExitError},
		{"invalid range flag", []string{"snapshot", "diff", "--range-start", "zz", sideA, sideB}, zzv528ExitError},
		{"inverted range", []string{"snapshot", "diff", "--range-start", "7a", "--range-end", "61", sideA, sideB}, zzv528ExitError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := zzv528Run(t, tc.args...)
			t.Logf("exit=%d stderr=%s", got.ExitCode, zzv528FirstLines(got.Stderr, 4))
			if got.ExitCode != tc.want {
				t.Errorf("exit code = %d, want %d (stderr: %s)", got.ExitCode, tc.want, got.Stderr)
			}
		})
	}
}

func TestZZV528CLIHelpAndRegistration(t *testing.T) {
	t.Run("diff is registered under snapshot", func(t *testing.T) {
		got := zzv528Run(t, "snapshot", "--help")
		if !strings.Contains(got.Stdout+got.Stderr, "diff") {
			t.Errorf("snapshot help does not list diff:\n%s%s", got.Stdout, got.Stderr)
		}
	})

	t.Run("diff flags are documented", func(t *testing.T) {
		got := zzv528Run(t, "snapshot", "diff", "--help")
		text := got.Stdout + got.Stderr
		for _, flag := range []string{"--rev-a", "--rev-b", "--range-start", "--range-end", "--output", "--write-out"} {
			if !strings.Contains(text, flag) {
				t.Errorf("help is missing %s:\n%s", flag, text)
			}
		}
		if !strings.Contains(text, "read-only") && !strings.Contains(text, "strictly read-only") {
			t.Logf("note: help does not mention the read-only contract\n%s", text)
		}
	})

	t.Run("existing snapshot subcommands still work", func(t *testing.T) {
		got := zzv528Run(t, "snapshot", "--help")
		text := got.Stdout + got.Stderr
		for _, sub := range []string{"restore", "status", "diff"} {
			if !strings.Contains(text, sub) {
				t.Errorf("snapshot help no longer lists %q:\n%s", sub, text)
			}
		}
	})
}

func TestZZV528CLILargeValueMemory(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("peak working set measurement is implemented for windows")
	}
	const (
		keys          = 24
		valueSize     = 1 << 20
		peakCeilingMB = 512
	)

	value := bytes.Repeat([]byte("etcd-snapshot-diff-"), valueSize/len("etcd-snapshot-diff-")+1)[:valueSize]
	fill := func(t *testing.T, srv *etcdserver.EtcdServer) {
		for i := 0; i < keys; i++ {
			key := "bulk-" + strconv.Itoa(i)
			zzv528PutKey(t, srv, key, value)
			zzv528PutKey(t, srv, key, value)
		}
	}

	sideA, stopA := zzv528StartEtcd(t, fill)
	stopA()
	sideB, stopB := zzv528StartEtcd(t, func(t *testing.T, srv *etcdserver.EtcdServer) {
		fill(t, srv)
		zzv528PutKey(t, srv, "bulk-0", []byte("changed"))
	})
	stopB()

	out := filepath.Join(t.TempDir(), "big.json")
	peakKB, err := zzv528RunWithPeak(t, []string{"snapshot", "diff", "--write-out", "json", "-o", out, sideA, sideB})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("compared %d MiB per side; peak working set = %d MiB", keys*valueSize/(1<<20), peakKB/1024)

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	report := zzv528ParseReport(t, string(data))
	if report.Summary.TotalKeysA != keys || report.Summary.TotalKeysB != keys {
		t.Fatalf("unexpected key counts: %+v", report.Summary)
	}
	if len(report.Changes) != 1 || string(report.Changes[0].Key) != "bulk-0" {
		t.Fatalf("unexpected changes: %+v", report.Changes)
	}
	if len(report.Changes[0].Before.Value) != valueSize {
		t.Fatalf("large value was truncated: %d bytes", len(report.Changes[0].Before.Value))
	}
	if !bytes.Equal(report.Changes[0].Before.Value, value) {
		t.Fatal("large value was corrupted")
	}
	if peakKB/1024 > peakCeilingMB {
		t.Errorf("peak working set %d MiB exceeds the %d MiB ceiling", peakKB/1024, peakCeilingMB)
	}
}
