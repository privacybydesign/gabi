package gabikeys_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/privacybydesign/gabi/gabikeys"
)

// Regression test for issue #56 (also #7): PrivateKey.WriteToFile must produce
// a file with mode 0600 in both the forceOverwrite=true and =false branches.
// Previously the forceOverwrite=true branch used os.Create, which yields
// 0666 & ^umask (typically 0644 — world-readable) for a file containing the
// issuer's private key.
func TestPrivateKeyWriteToFilePermissions(t *testing.T) {
	// Neutralize the test runner's umask so we verify the mode we passed,
	// not whatever the environment happened to strip.
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := t.TempDir()
	priv := &gabikeys.PrivateKey{}

	t.Run("forceOverwrite=false on fresh path", func(t *testing.T) {
		path := filepath.Join(dir, "priv-noforce.xml")
		if _, err := priv.WriteToFile(path, false); err != nil {
			t.Fatalf("WriteToFile: %v", err)
		}
		assertPerm(t, path, 0600)
	})

	t.Run("forceOverwrite=true on fresh path", func(t *testing.T) {
		path := filepath.Join(dir, "priv-force-fresh.xml")
		if _, err := priv.WriteToFile(path, true); err != nil {
			t.Fatalf("WriteToFile: %v", err)
		}
		assertPerm(t, path, 0600)
	})

	t.Run("forceOverwrite=true over existing file", func(t *testing.T) {
		// This is the actual regression path: a caller rotating/replacing
		// an on-disk key. Pre-create the file with permissive perms to
		// catch any implementation that preserves existing modes.
		path := filepath.Join(dir, "priv-force-overwrite.xml")
		if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		if _, err := priv.WriteToFile(path, true); err != nil {
			t.Fatalf("WriteToFile: %v", err)
		}
		assertPerm(t, path, 0600)
	})
}

// Companion test for PublicKey.WriteToFile. Not a security issue, but the
// fix in #56 made both branches consistent at 0644 — guard against
// regressions there too. We only assert on freshly created files: open(2)
// preserves the mode of pre-existing files and the public key path does
// not (and should not) force-loosen tighter perms a deployer may have set.
func TestPublicKeyWriteToFilePermissions(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := t.TempDir()
	pub := &gabikeys.PublicKey{}

	t.Run("forceOverwrite=false on fresh path", func(t *testing.T) {
		path := filepath.Join(dir, "pub-noforce.xml")
		if _, err := pub.WriteToFile(path, false); err != nil {
			t.Fatalf("WriteToFile: %v", err)
		}
		assertPerm(t, path, 0644)
	})

	t.Run("forceOverwrite=true on fresh path", func(t *testing.T) {
		path := filepath.Join(dir, "pub-force-fresh.xml")
		if _, err := pub.WriteToFile(path, true); err != nil {
			t.Fatalf("WriteToFile: %v", err)
		}
		assertPerm(t, path, 0644)
	})
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s: mode = %#o, want %#o", path, got, want)
	}
}
