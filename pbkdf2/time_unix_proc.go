//
// Written by Maxim Khitrov (October 2012)
//

// +build !freebsd,!linux,!windows

package pbkdf2

import (
	"syscall"
	"time"
)

func utime() time.Duration {
	var u syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &u); err != nil {
		panic(err)
	}
	return time.Duration(u.Utime.Nano())
}
