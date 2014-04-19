//
// Written by Maxim Khitrov (October 2012)
//

// +build freebsd linux

package pbkdf2

import (
	"syscall"
	"time"
)

var getrusage_who = syscall.RUSAGE_THREAD

func init() {
	var u syscall.Rusage
	if syscall.Getrusage(getrusage_who, &u) == syscall.EINVAL {
		getrusage_who = syscall.RUSAGE_SELF
	}
}

func utime() time.Duration {
	var u syscall.Rusage
	if err := syscall.Getrusage(getrusage_who, &u); err != nil {
		panic(err)
	}
	return time.Duration(u.Utime.Nano())
}
