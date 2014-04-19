//
// Written by Maxim Khitrov (October 2012)
//

package pbkdf2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func TestRFC6070(t *testing.T) {
	tests := []struct {
		P, S  string
		c     []int
		dkLen int
		out   string
	}{
		{"password", "salt", []int{1}, 20,
			"0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6"},
		{"password", "salt", []int{2}, 20,
			"ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57"},
		{"password", "salt", []int{1, 1}, 20,
			"ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57"},
		{"password", "salt", []int{4096}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		{"password", "salt", []int{1, 4095}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		{"password", "salt", []int{2048, 2048}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		{"password", "salt", []int{4095, 1}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		{"password", "salt", []int{1, 4094, 1}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		//{"password", "salt", []int{16777216}, 20,
		//	"ee fe 3d 61 cd 4d a4 e4 e9 94 5b 3d 6b a2 15 8c 26 34 e9 84"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", []int{4096}, 25,
			"3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38"},
		{"pass\x00word", "sa\x00lt", []int{4096}, 16,
			"56 fa 6a a7 55 48 09 9d cc 37 d7 f0 34 25 e0 c3"},
	}
	var dk []byte
	for _, test := range tests {
		kdf := New([]byte(test.P), []byte(test.S), test.dkLen, sha1.New)
		for _, c := range test.c {
			dk = kdf.Next(c)
		}
		if out := fmt.Sprintf("% x", dk); out != test.out {
			t.Errorf("kdf.Next() expected %q; got %q", test.out, out)
		}
	}
}

func TestKeyGen(t *testing.T) {
	kdf := New([]byte("pass"), []byte("salt"), 10, sha256.New)
	key := kdf.Derive(100 * time.Millisecond)
	itr := kdf.Iters()

	tryKey := func(dk []byte) error {
		if bytes.Equal(dk, key) {
			return KeyFound
		}
		return nil
	}

	d := 10 * time.Millisecond
	dk, err := kdf.Search(d, tryKey)
	if dk != nil || err != ErrTimeout {
		t.Errorf("kdf.Search(%v) expected ErrTimeout; got % x (%v)", d, dk, err)
	}

	d = 200 * time.Millisecond
	dk, err = kdf.Search(d, tryKey)
	if !bytes.Equal(dk, key) || err != nil {
		t.Errorf("kdf.Search(%v) expected % x; got % x (%v)", d, key, dk, err)
	}

	if kdf.Iters() != itr {
		t.Errorf("kdf.Iters() expected %v; got %v", itr, kdf.Iters())
	}
}
