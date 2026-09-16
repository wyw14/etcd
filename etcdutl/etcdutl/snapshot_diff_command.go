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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"go.etcd.io/etcd/etcdutl/v3/snapshot"
	"go.etcd.io/etcd/pkg/v3/cobrautl"
)

const (
	diffFormatSimple = "simple"
	diffFormatJSON   = "json"
)

// snapshotDiffOptions holds the flags of "snapshot diff".
type snapshotDiffOptions struct {
	revisionA  int64
	revisionB  int64
	rangeStart []byte
	rangeEnd   []byte
	outputPath string
}

// errDiffOutput marks failures happening while publishing the report, so
// that the CLI can exit with the dedicated I/O exit code.
var errDiffOutput = errors.New("failed to write snapshot diff report")

// NewSnapshotDiffCommand returns the cobra command for "snapshot diff".
func NewSnapshotDiffCommand() *cobra.Command {
	o := &snapshotDiffOptions{}
	cmd := &cobra.Command{
		Use:   "diff <filename-a> <filename-b>",
		Short: "Compares the business keys of two offline snapshots",
		Long: `Reports the business key differences between two snapshots at the selected
revisions. Differences are reported in key byte order as added, deleted or
modified keys; modified keys distinguish value changes from create revision,
mod revision, version and lease binding changes.

Both snapshot files are opened strictly read-only. The comparison reads side
<filename-a> at --rev-a and side <filename-b> at --rev-b (0 means the latest
readable revision of each side), and reports how the keyspace changes from A
to B. Keys and values are binary safe; JSON output encodes them as base64.

The report is published only after the comparison completed successfully:
on snapshot corruption, compacted/future revisions, output failure or
cancellation the command exits with an error without writing a partial
result file.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			outputFormat, err := cmd.Flags().GetString("write-out")
			if err != nil {
				cobrautl.ExitWithError(cobrautl.ExitError, err)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			if err := runSnapshotDiff(ctx, args[0], args[1], *o, outputFormat); err != nil {
				cobrautl.ExitWithError(diffExitCode(err), err)
			}
		},
	}

	cmd.Flags().Int64Var(&o.revisionA, "rev-a", 0, "revision to read from snapshot A (0 = latest readable revision)")
	cmd.Flags().Int64Var(&o.revisionB, "rev-b", 0, "revision to read from snapshot B (0 = latest readable revision)")
	cmd.Flags().BytesHexVar(&o.rangeStart, "range-start", nil, "first key to compare, hex bytes, e.g. 666f6f (default: first key)")
	cmd.Flags().BytesHexVar(&o.rangeEnd, "range-end", nil, "key range end (exclusive), hex bytes; a single zero byte 00 means an open upper bound")
	cmd.Flags().StringVarP(&o.outputPath, "output", "o", "", "write the report to the file instead of standard output (published atomically)")
	cmd.MarkFlagFilename("output")

	return cmd
}

// diffExitCode maps comparison failures onto the conventional exit codes.
func diffExitCode(err error) int {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return cobrautl.ExitInterrupted
	case errors.Is(err, errDiffOutput):
		return cobrautl.ExitIO
	case errors.Is(err, snapshot.ErrRevisionCompacted), errors.Is(err, snapshot.ErrRevisionInFuture):
		return cobrautl.ExitBadArgs
	default:
		return cobrautl.ExitError
	}
}

// runSnapshotDiff performs the comparison and publishes the report.
//
// Change records are streamed into a temporary spool file while the snapshots
// are being scanned, so neither values nor the report accumulate in memory.
// The report header requires the resolved revisions and the report must never
// be partially observable, so the final output is assembled only after the
// comparison completed: it is either copied to standard output or written to
// a sibling temporary file and atomically renamed over the destination.
func runSnapshotDiff(ctx context.Context, pathA, pathB string, o snapshotDiffOptions, format string) error {
	switch format {
	case diffFormatSimple, diffFormatJSON:
	default:
		return fmt.Errorf("%w: %q", errors.New("unsupported output format"), format)
	}

	cfg := snapshot.CompareConfig{
		SnapshotAPath: pathA,
		SnapshotBPath: pathB,
		RevisionA:     o.revisionA,
		RevisionB:     o.revisionB,
		RangeStart:    o.rangeStart,
		RangeEnd:      o.rangeEnd,
	}

	spool, err := os.CreateTemp("", "etcdutl-snapshot-diff-*.body")
	if err != nil {
		return fmt.Errorf("%w: cannot create temporary spool file: %v", errDiffOutput, err)
	}
	spoolPath := spool.Name()
	defer os.Remove(spoolPath)

	bodyWriter := newDiffBodyWriter(format, spool)
	summary, err := snapshot.Compare(ctx, cfg, func(change snapshot.KeyChange) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return bodyWriter.writeChange(change)
	})
	if err != nil {
		spool.Close()
		return err
	}
	if err := bodyWriter.close(); err != nil {
		spool.Close()
		return fmt.Errorf("%w: %v", errDiffOutput, err)
	}
	if err := spool.Close(); err != nil {
		return fmt.Errorf("%w: %v", errDiffOutput, err)
	}

	if err := publishDiffReport(format, o.outputPath, summary, spoolPath); err != nil {
		return err
	}
	return nil
}

// publishDiffReport renders the complete report to standard output or
// atomically replaces the destination file.
func publishDiffReport(format, outputPath string, summary snapshot.CompareSummary, spoolPath string) (err error) {
	render := func(w io.Writer) error {
		body, err := os.Open(spoolPath)
		if err != nil {
			return err
		}
		defer body.Close()
		return renderDiffReport(format, w, summary, body)
	}

	if outputPath == "" {
		if err := render(os.Stdout); err != nil {
			return fmt.Errorf("%w: %v", errDiffOutput, err)
		}
		return nil
	}

	dir := filepath.Dir(outputPath)
	tmp, err := os.CreateTemp(dir, ".etcdutl-snapshot-diff-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: %v", errDiffOutput, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { os.Remove(tmpPath) }
	if err := render(tmp); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("%w: %v", errDiffOutput, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("%w: %v", errDiffOutput, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("%w: %v", errDiffOutput, err)
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		cleanup()
		return fmt.Errorf("%w: %v", errDiffOutput, err)
	}
	return nil
}

// diffBodyWriter streams per-change records into the spool. JSON records are
// one compact JSON object per line; simple records are human-readable lines.
type diffBodyWriter struct {
	format string
	w      *bufio.Writer
	f      *os.File
	enc    *json.Encoder
}

func newDiffBodyWriter(format string, f *os.File) *diffBodyWriter {
	bw := bufio.NewWriterSize(f, 64*1024)
	dw := &diffBodyWriter{format: format, f: f, w: bw}
	if format == diffFormatJSON {
		dw.enc = json.NewEncoder(bw)
		dw.enc.SetEscapeHTML(false)
	}
	return dw
}

func (dw *diffBodyWriter) writeChange(change snapshot.KeyChange) error {
	switch dw.format {
	case diffFormatJSON:
		return dw.enc.Encode(change)
	default:
		_, err := dw.w.WriteString(formatSimpleChange(change))
		return err
	}
}

func (dw *diffBodyWriter) close() error {
	return dw.w.Flush()
}

// renderDiffReport assembles the final report from the spooled change body.
func renderDiffReport(format string, w io.Writer, summary snapshot.CompareSummary, body io.ReadSeeker) error {
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return err
	}
	switch format {
	case diffFormatJSON:
		return renderJSONDiffReport(w, summary, body)
	default:
		return renderSimpleDiffReport(w, summary, body)
	}
}

func renderJSONDiffReport(w io.Writer, summary snapshot.CompareSummary, body io.Reader) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	marshal := func(v any) (string, error) {
		buf.Reset()
		if err := enc.Encode(v); err != nil {
			return "", err
		}
		return strings.TrimRight(buf.String(), "\n"), nil
	}

	sideA, err := marshal(summary.A)
	if err != nil {
		return err
	}
	sideB, err := marshal(summary.B)
	if err != nil {
		return err
	}
	keyRange, err := marshal(summary.Range)
	if err != nil {
		return err
	}
	counters, err := marshal(struct {
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
	}{
		TotalKeysA:            summary.TotalKeysA,
		TotalKeysB:            summary.TotalKeysB,
		Added:                 summary.Added,
		Deleted:               summary.Deleted,
		Modified:              summary.Modified,
		ValueChanged:          summary.ValueChanged,
		CreateRevisionChanged: summary.CreateRevisionChanged,
		ModRevisionChanged:    summary.ModRevisionChanged,
		VersionChanged:        summary.VersionChanged,
		LeaseChanged:          summary.LeaseChanged,
		Equal:                 summary.Equal,
	})
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "{\n  \"status\": \"complete\",\n  \"a\": %s,\n  \"b\": %s,\n  \"range\": %s,\n  \"changes\": [",
		sideA, sideB, keyRange); err != nil {
		return err
	}

	reader := bufio.NewReaderSize(body, 64*1024)
	first := true
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 && len(bytes.TrimSpace([]byte(line))) > 0 {
			separator := ",\n    "
			if first {
				separator = "\n    "
				first = false
			}
			if _, err := io.WriteString(w, separator); err != nil {
				return err
			}
			if _, err := io.WriteString(w, strings.TrimRight(line, "\n")); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if !first {
		if _, err := io.WriteString(w, "\n  "); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "],\n  \"summary\": %s\n}\n", counters)
	return err
}

func renderSimpleDiffReport(w io.Writer, summary snapshot.CompareSummary, body io.Reader) error {
	if _, err := fmt.Fprintln(w, "Snapshot diff (A => B)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "A:", formatSimpleSide(summary.A)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "B:", formatSimpleSide(summary.B)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Range:", formatSimpleRange(summary.Range)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Changes (key byte order):"); err != nil {
		return err
	}
	if _, err := io.Copy(w, body); err != nil {
		return err
	}
	if summary.Equal {
		if _, err := fmt.Fprintln(w, "No differences found."); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w,
		"Summary: added=%d deleted=%d modified=%d (value=%d create_revision=%d mod_revision=%d version=%d lease=%d); live keys A=%d B=%d\nResult: %s\n",
		summary.Added, summary.Deleted, summary.Modified,
		summary.ValueChanged, summary.CreateRevisionChanged, summary.ModRevisionChanged, summary.VersionChanged, summary.LeaseChanged,
		summary.TotalKeysA, summary.TotalKeysB,
		map[bool]string{true: "EQUAL", false: "DIFFERENT"}[summary.Equal])
	return err
}

func formatSimpleSide(info snapshot.SideRevisionInfo) string {
	return fmt.Sprintf("path=%s requested_revision=%s revision=%d latest_revision=%d compact_revision=%d",
		quoteBytes([]byte(info.Path)),
		formatRequestedRevision(info.RequestedRevision),
		info.Revision, info.LatestRevision, info.CompactRevision)
}

func formatRequestedRevision(rev int64) string {
	if rev == 0 {
		return "latest"
	}
	return strconv.FormatInt(rev, 10)
}

func formatSimpleRange(keyRange snapshot.KeyRange) string {
	start := "(beginning)"
	if len(keyRange.Start) > 0 {
		start = quoteBytes(keyRange.Start)
	}
	end := "(open)"
	if len(keyRange.End) > 0 && !bytes.Equal(keyRange.End, []byte{0}) {
		end = quoteBytes(keyRange.End)
	}
	return fmt.Sprintf("start=%s end=%s", start, end)
}

// quoteBytes renders arbitrary bytes losslessly with Go quoting; invalid UTF-8
// bytes are emitted as \xHH escapes and can be parsed back with
// strconv.Unquote.
func quoteBytes(b []byte) string {
	return strconv.Quote(string(b))
}

func formatLease(lease int64) string {
	if lease == 0 {
		return "none"
	}
	return strconv.FormatInt(lease, 10)
}

func formatSimpleState(state *snapshot.KeyState) string {
	return fmt.Sprintf("value=%s create_revision=%d mod_revision=%d version=%d lease=%s",
		quoteBytes(state.Value), state.CreateRevision, state.ModRevision, state.Version, formatLease(state.Lease))
}

func formatSimpleChange(change snapshot.KeyChange) string {
	switch change.Type {
	case snapshot.ChangeAdded:
		return fmt.Sprintf("ADDED    key=%s %s\n", quoteBytes(change.Key), formatSimpleState(change.After))
	case snapshot.ChangeDeleted:
		return fmt.Sprintf("DELETED  key=%s %s\n", quoteBytes(change.Key), formatSimpleState(change.Before))
	case snapshot.ChangeModified:
		var sb strings.Builder
		fmt.Fprintf(&sb, "MODIFIED key=%s\n", quoteBytes(change.Key))
		if change.ValueChanged {
			fmt.Fprintf(&sb, "         value: %s => %s\n", quoteBytes(change.Before.Value), quoteBytes(change.After.Value))
		}
		if change.CreateRevisionChanged {
			fmt.Fprintf(&sb, "         create_revision: %d => %d\n", change.Before.CreateRevision, change.After.CreateRevision)
		}
		if change.ModRevisionChanged {
			fmt.Fprintf(&sb, "         mod_revision: %d => %d\n", change.Before.ModRevision, change.After.ModRevision)
		}
		if change.VersionChanged {
			fmt.Fprintf(&sb, "         version: %d => %d\n", change.Before.Version, change.After.Version)
		}
		if change.LeaseChanged {
			fmt.Fprintf(&sb, "         lease: %s => %s\n", formatLease(change.Before.Lease), formatLease(change.After.Lease))
		}
		return sb.String()
	default:
		return ""
	}
}
