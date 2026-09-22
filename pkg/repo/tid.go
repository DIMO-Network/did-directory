package repo

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TIDs are atproto timestamp identifiers: 13 characters of base32-sortable
// encoding a 64-bit integer whose top bit is zero, next 53 bits are microseconds
// since the Unix epoch and low 10 bits are a clock identifier. They sort by
// time as strings, which is what makes them usable as record keys and revisions.

const tidAlphabet = "234567abcdefghijklmnopqrstuvwxyz"

// TIDLength is the length of an encoded TID.
const TIDLength = 13

var tidClock = struct {
	sync.Mutex
	last uint64
	id   uint64
}{}

func init() {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("repo: seed TID clock id: %v", err))
	}
	tidClock.id = uint64(binary.BigEndian.Uint16(b[:])) & 0x3ff
}

// NewTID returns a fresh TID, strictly greater than any this process has
// issued before, so two commits in the same microsecond still order.
func NewTID() string {
	return tidAt(time.Now())
}

func tidAt(t time.Time) string {
	us := uint64(t.UnixMicro()) & ((1 << 53) - 1)
	v := us<<10 | tidClock.id
	tidClock.Lock()
	if v <= tidClock.last {
		v = tidClock.last + 1
	}
	tidClock.last = v
	tidClock.Unlock()
	return encodeTID(v)
}

func encodeTID(v uint64) string {
	var out [TIDLength]byte
	for i := TIDLength - 1; i >= 0; i-- {
		out[i] = tidAlphabet[v&0x1f]
		v >>= 5
	}
	return string(out[:])
}

// ValidateTID checks that s is a well-formed TID.
func ValidateTID(s string) error {
	if len(s) != TIDLength {
		return fmt.Errorf("TID must be %d characters, got %d", TIDLength, len(s))
	}
	for i := 0; i < len(s); i++ {
		if indexOfTIDChar(s[i]) < 0 {
			return fmt.Errorf("TID %q: byte %q is not base32-sortable", s, s[i])
		}
	}
	// 13 characters carry 65 bits. The first character holds the top five, of
	// which the two highest, bit 64 and the sign bit 63, must be zero.
	if indexOfTIDChar(s[0]) > 0x07 {
		return errors.New("TID overflows 64 bits")
	}
	return nil
}

// TIDTime returns the timestamp a TID encodes.
func TIDTime(s string) (time.Time, error) {
	if err := ValidateTID(s); err != nil {
		return time.Time{}, err
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		v = v<<5 | uint64(indexOfTIDChar(s[i]))
	}
	return time.UnixMicro(int64(v >> 10)).UTC(), nil
}

func indexOfTIDChar(c byte) int {
	for i := 0; i < len(tidAlphabet); i++ {
		if tidAlphabet[i] == c {
			return i
		}
	}
	return -1
}
