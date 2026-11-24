package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// readSecretFile reads a file holding private key material, refusing one that
// group or others may read or write, as ssh does: a shared host's other users
// would otherwise sign with it. Windows has no such mode bits to check.
func readSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if perm := fi.Mode().Perm(); runtime.GOOS != "windows" && perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by group or others (mode %04o); run chmod 600 %s", path, perm, path)
	}
	return io.ReadAll(f)
}

// writeSecretFile writes data to path and leaves it 0600, also when the file
// already existed with a looser mode (os.WriteFile sets the mode only on a
// file it creates). The mode is tightened before the write too, so the new
// contents are never readable by others.
func writeSecretFile(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
