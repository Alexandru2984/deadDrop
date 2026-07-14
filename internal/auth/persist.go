package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func loadOrCreateSecret(path string, size int) ([]byte, error) {
	if size < 16 {
		return nil, errors.New("secret size is too small")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	read := func() ([]byte, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("secret %s is not a regular file", filepath.Base(path))
		}
		secret, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(secret) != size {
			return nil, fmt.Errorf("secret %s has invalid length", filepath.Base(path))
		}
		if err := os.Chmod(path, 0600); err != nil {
			return nil, err
		}
		return secret, nil
	}
	if secret, err := read(); err == nil {
		return secret, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpName)
	}()
	if err := f.Chmod(0600); err != nil {
		return nil, err
	}
	if _, err := f.Write(secret); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	// Link publishes the fully-written inode atomically and refuses to replace an
	// existing secret. If another process won the race, use its complete value.
	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			return read()
		}
		return nil, err
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return nil, err
	}
	if err := d.Close(); err != nil {
		return nil, err
	}
	return secret, nil
}

// atomicWriteJSON durably replaces a private JSON file without following a
// predictable temporary-file path. Callers hold their logical store lock.
func atomicWriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync auth data directory: %w", err)
	}
	return nil
}
