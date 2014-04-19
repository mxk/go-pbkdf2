//
// Written by Maxim Khitrov (October 2012)
//

package pbkdf2

import (
	"syscall"
	"time"
	"unsafe"
)

/*
Note: GetThreadTimes function may return inaccurate values when the calling
thread is frequently interrupted prior to consuming all of its quantum. This
shouldn't be a huge problem for PBKDF2 calculation since it doesn't enter any
wait states, but some additional testing in high-load situations is needed.

http://blog.kalmbachnet.de/?postid=28
http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-10/0689.html
*/

var (
	modkernel32 = syscall.MustLoadDLL("kernel32.dll")

	procGetCurrentThread = modkernel32.MustFindProc("GetCurrentThread")
	procGetThreadTimes   = modkernel32.MustFindProc("GetThreadTimes")
)

func utime() time.Duration {
	var u syscall.Rusage
	h, _ := getCurrentThread()
	err := getThreadTimes(h, &u.CreationTime, &u.ExitTime, &u.KernelTime, &u.UserTime)
	if err != nil {
		panic(err)
	}
	t := uint64(u.UserTime.HighDateTime)<<32 | uint64(u.UserTime.LowDateTime)
	return time.Duration(t * 100)
}

func getCurrentThread() (pseudoHandle syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procGetCurrentThread.Addr(), 0, 0, 0, 0)
	pseudoHandle = syscall.Handle(r0)
	if pseudoHandle == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func getThreadTimes(handle syscall.Handle, creationTime, exitTime, kernelTime, userTime *syscall.Filetime) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetThreadTimes.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(creationTime)), uintptr(unsafe.Pointer(exitTime)), uintptr(unsafe.Pointer(kernelTime)), uintptr(unsafe.Pointer(userTime)), 0)
	if int(r1) == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
