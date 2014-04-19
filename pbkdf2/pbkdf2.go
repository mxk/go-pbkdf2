//
// Written by Maxim Khitrov (October 2012)
//

/*
Package pbkdf2 provides an incremental version of the PBKDF2 key derivation
algorithm, as described in RFC 2898.

Password-Based Key Derivation Function 2 derives cryptographic keys of a
specified length from the provided password and salt values. The derivation is
performed by a CPU-bound loop, with the iteration count specified as one of the
function parameters. The higher the iteration count, the more difficult (time
consuming) it is for an attacker to brute-force the password/salt combination.

An incremental PBKDF2 implementation allows the key derivation loop to resume
execution from its previous state. This allows the user to derive keys after
1000 and 2000 iterations, for example, without having to recompute the first
1000 iterations twice. The package uses this feature to implement time-based key
derivation functions (see Derive and Search methods), which gradually increment
the iteration count until the time limit is reached.
*/
package pbkdf2

import (
	"crypto/hmac"
	"errors"
	"hash"
	"runtime"
	"time"
)

// precision determines the timing accuracy of Derive and Search methods by
// varying the exponential growth rate of the iteration count. The derivation
// begins with 1024 iterations and the count is incremented exponentially at the
// rate of 1/(2^precision). The minimum precision is 0 (100% growth rate) and
// the maximum is 10 (0.1% growth rate). The theoretical timing error is plus or
// minus timelimit*rate/(rate+2).
//
// A higher precision results in more accurate timing, but at the expense of
// having to make many additional calls to the callback function when searching
// for a previously derived key. A precision of 4 (6.25%) is a good compromise,
// which covers 2^32 iterations in 252 steps with a timing error of 3%.
const precision = 4

// KeyFound is returned by the PBKDF2.Search callback function to indicate that
// the correct key was found.
var KeyFound = errors.New("pbkdf2: key found")

// ErrTimeout is returned by PBKDF2.Search when a valid key is not found in the
// allocated time.
var ErrTimeout = errors.New("pbkdf2: key search timeout")

// Key derives a key from the password, salt, and iteration count, returning a
// []byte of length dkLen that can be used as cryptographic key. This function
// provides compatibility with the go.crypto/pbkdf2 package.
func Key(pass, salt []byte, iter, dkLen int, h func() hash.Hash) []byte {
	return New(pass, salt, dkLen, h).Next(iter)
}

type PBKDF2 struct {
	prf   hash.Hash // HMAC
	dkLen int       // Key length returned by key derivation methods
	salt  []byte    // Salt value used in the first iteration
	t     []byte    // Current T values (len >= dkLen, multiple of prf.Size())
	u     []byte    // Current U values (same len as t)
	iters int       // Current iteration count
}

// New returns a new PBKDF2 state initialized to zero iterations.
func New(pass, salt []byte, dkLen int, h func() hash.Hash) *PBKDF2 {
	return &PBKDF2{prf: hmac.New(h, pass), dkLen: dkLen, salt: dup(salt)}
}

// Derive derives a new key in time d.
func (kdf *PBKDF2) Derive(d time.Duration) []byte {
	dk, _ := kdf.derive(d, precision, func([]byte) error { return nil })
	return dk
}

// Search tries to find a previously derived key. The callback function f is
// used to test the current key after each step in the derivation process. This
// test must be reasonably fast to maintain accurate derivation timing. The
// search stops when f returns a non-nil error or the time limit is reached. The
// correct key is found when f returns KeyFound.
//
// As a general rule, Search should be given more time than Derive, especially
// if the two operations are being performed on different computers. If Derive
// was given 1 second, a reasonable limit for Search is 3 to 5 seconds.
func (kdf *PBKDF2) Search(d time.Duration, f func(dk []byte) error) (dk []byte, err error) {
	if dk, err = kdf.derive(d, precision, f); err == KeyFound {
		err = nil
	} else {
		dk = nil
		if err == nil {
			err = ErrTimeout
		}
	}
	return
}

// Next runs the key derivation algorithm for c additional iterations and
// returns a copy of the new key.
func (kdf *PBKDF2) Next(c int) []byte {
	if c <= 0 {
		panic("pbkdf2: invalid iteration count")
	}
	prf := kdf.prf
	hLen := prf.Size()

	if kdf.iters == 0 {
		n := (kdf.dkLen + hLen - 1) / hLen
		t := make([]byte, 0, 2*n*hLen)
		for i := 1; i <= n; i++ {
			prf.Reset()
			prf.Write(kdf.salt)
			prf.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
			t = prf.Sum(t)
		}
		kdf.t, kdf.u = t, t[len(t):cap(t)]
		copy(kdf.u, kdf.t)
		c--
		kdf.iters = 1
	}

	t, u := kdf.t, kdf.u
	for i := 0; i < c; i++ {
		for j := 0; j < len(u); j += hLen {
			prf.Reset()
			prf.Write(u[j : j+hLen])
			prf.Sum(u[:j])
		}
		for j, v := range u {
			t[j] ^= v
		}
	}
	kdf.iters += c
	return dup(t[:kdf.dkLen])
}

// Salt returns a copy of the current salt value.
func (kdf *PBKDF2) Salt() []byte {
	return dup(kdf.salt)
}

// Size returns the derived key size.
func (kdf *PBKDF2) Size() int {
	return kdf.dkLen
}

// Iters returns the total number of iterations performed so far.
func (kdf *PBKDF2) Iters() int {
	return kdf.iters
}

// Reset returns kdf to the initial state at zero iterations. Salt and dkLen
// parameters for subsequent iterations can be changed by passing non-nil and
// non-zero values, respectively.
func (kdf *PBKDF2) Reset(salt []byte, dkLen int) {
	if dkLen > 0 {
		kdf.dkLen = dkLen
	}
	if salt != nil {
		kdf.salt = dup(salt)
	}
	kdf.t = nil
	kdf.u = nil
	kdf.iters = 0
}

// derive performs time-based key derivation.
func (kdf *PBKDF2) derive(d time.Duration, p uint, f func(dk []byte) error) (dk []byte, err error) {
	if p > 10 {
		panic("pbkdf2: invalid derivation precision")
	}
	kdf.Reset(nil, 0)
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		runtime.LockOSThread()
		r := 1.0 / float64(uint(1)<<p)
		d -= time.Duration(float64(d) * r / (r + 2))
		t := timer{time.Now(), utime()}
		dk = kdf.Next(1024)
		for {
			if err = f(dk); err != nil || t.elapsed(d) {
				return
			}
			dk = kdf.Next(kdf.iters >> p)
		}
	}()
	<-ch
	return
}

type timer struct {
	wall time.Time
	user time.Duration
}

// elapsed returns true when time d has elapsed from the point when the timer
// was created. Timing is done according to the user CPU time of the current
// thread with the wall clock time acting as a backup. Systems that don't
// provide per-thread timing information use the process CPU time instead. The
// wall clock time defines lower (d) and upper (2*d) limits as a workaround for
// inaccurate CPU time accounting on some systems (e.g. Windows).
func (t *timer) elapsed(d time.Duration) bool {
	wall := time.Since(t.wall)
	emin := wall >= d
	if emin && wall < d<<1 {
		return utime()-t.user >= d
	}
	return emin
}

func dup(b []byte) []byte {
	t := make([]byte, len(b))
	copy(t, b)
	return t
}
