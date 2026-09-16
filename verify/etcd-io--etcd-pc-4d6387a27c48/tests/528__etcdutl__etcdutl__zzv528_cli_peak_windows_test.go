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

//go:build windows

package etcdutl_test

import (
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	zzv528Psapi                    = windows.NewLazySystemDLL("psapi.dll")
	zzv528GetProcessMemoryInfoProc = zzv528Psapi.NewProc("GetProcessMemoryInfo")
	zzv528CountersSize             = uint32(unsafe.Sizeof(zzv528ProcessMemoryCountersEx{}))
)

type zzv528ProcessMemoryCountersEx struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// zzv528RunWithPeak runs etcdutl and reports the peak working set of the real
// child process in KiB. The counters are read from the process handle after it
// exited, so the value covers exactly one comparison and cannot be polluted by
// the embedded servers used to build the fixtures.
func zzv528RunWithPeak(t *testing.T, args []string) (int, error) {
	t.Helper()

	cmd := exec.Command(zzv528Etcdutl(t), args...)
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 0, err
	}
	defer windows.CloseHandle(handle)

	waitErr := cmd.Wait()

	var counters zzv528ProcessMemoryCountersEx
	counters.Cb = zzv528CountersSize
	ret, _, callErr := zzv528GetProcessMemoryInfoProc.Call(
		uintptr(handle), uintptr(unsafe.Pointer(&counters)), uintptr(zzv528CountersSize))
	if ret == 0 {
		return 0, callErr
	}
	return int(counters.PeakWorkingSetSize / 1024), waitErr
}
