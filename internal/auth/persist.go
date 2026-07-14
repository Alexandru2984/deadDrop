package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const rootTempAttempts = 100

// openPrivateRoot anchors subsequent operations to the selected directory.
// os.Root rejects absolute links and links that escape that directory, avoiding
// path re-resolution races while private auth files are read or replaced.
func openPrivateRoot(path string) (*os.Root, string, error) {
	clean := filepath.Clean(path)
	dir, name := filepath.Dir(clean), filepath.Base(clean)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return nil, "", errors.New("invalid private file path")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", err
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, "", err
	}
	if !dirInfo.IsDir() {
		return nil, "", errors.New("private data root is not a real directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(dirInfo, rootInfo) {
		_ = root.Close()
		return nil, "", errors.New("private data root changed while opening")
	}
	if err := root.Chmod(".", 0700); err != nil { // #nosec G302 -- directories require execute permission
		_ = root.Close()
		return nil, "", err
	}
	return root, name, nil
}

func createPrivateTemp(root *os.Root, prefix string) (*os.File, string, error) {
	var random [8]byte
	for range rootTempAttempts {
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err == nil {
			return file, name, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate private temporary file")
}

func syncRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func loadOrCreateSecret(path string, size int) ([]byte, error) {
	if size < 16 {
		return nil, errors.New("secret size is too small")
	}
	root, name, err := openPrivateRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	read := func() ([]byte, error) {
		pathInfo, err := root.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !pathInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("secret %s is not a regular file", name)
		}
		file, err := root.Open(name)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("secret %s is not a regular file", name)
		}
		if err := file.Chmod(0600); err != nil {
			return nil, err
		}
		secret, err := io.ReadAll(io.LimitReader(file, int64(size+1)))
		if err != nil {
			return nil, err
		}
		if len(secret) != size {
			return nil, fmt.Errorf("secret %s has invalid length", name)
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
	f, tmpName, err := createPrivateTemp(root, "."+name+"-")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
		_ = root.Remove(tmpName)
	}()
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
	if err := root.Link(tmpName, name); err != nil {
		if os.IsExist(err) {
			return read()
		}
		return nil, err
	}
	if err := syncRoot(root); err != nil {
		return nil, err
	}
	return secret, nil
}

// atomicWriteJSON durably replaces a private JSON file without following a
// predictable temporary-file path. Callers hold their logical store lock.
func atomicWriteJSONAt(root *os.Root, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, tmpName, err := createPrivateTemp(root, "."+name+"-")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = root.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmpName, name); err != nil {
		return err
	}
	if err := syncRoot(root); err != nil {
		return fmt.Errorf("sync auth data directory: %w", err)
	}
	return nil
}

func atomicWriteJSON(path string, value any) error {
	root, name, err := openPrivateRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return atomicWriteJSONAt(root, name, value)
}
