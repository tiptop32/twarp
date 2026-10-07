package resolver

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const nameserver = "172.19.0.2"

func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = string(data)
	}
	return files
}

func TestSyncWritesManagedFilesAndKeepsForeignOnes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "resolver")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := "nameserver 192.0.2.1\n"
	if err := os.WriteFile(filepath.Join(dir, "corp.example"), []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Sync(dir, []string{"intra.example", "corp.example", "intra.example"}, nameserver)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !reflect.DeepEqual(result.Foreign, []string{"corp.example"}) {
		t.Fatalf("Sync() = %+v, want changed with foreign corp.example", result)
	}
	managedContent := marker + "\nnameserver " + nameserver + "\n"
	want := map[string]string{"corp.example": foreign, "intra.example": managedContent}
	if got := readDir(t, dir); !reflect.DeepEqual(got, want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
	info, err := os.Stat(filepath.Join(dir, "intra.example"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("managed file mode = %v, error = %v, want 0644", info.Mode().Perm(), err)
	}

	result, err = Sync(dir, []string{"intra.example", "corp.example"}, nameserver)
	if err != nil || result.Changed {
		t.Fatalf("second Sync() = (%+v, %v), want no change", result, err)
	}
}

func TestSyncRemovesManagedFilesForDroppedDomains(t *testing.T) {
	dir := t.TempDir()
	if _, err := Sync(dir, []string{"old.example", "kept.example"}, nameserver); err != nil {
		t.Fatal(err)
	}
	result, err := Sync(dir, []string{"kept.example"}, nameserver)
	if err != nil || !result.Changed {
		t.Fatalf("Sync() = (%+v, %v), want change", result, err)
	}
	if got := readDir(t, dir); len(got) != 1 || got["kept.example"] == "" {
		t.Fatalf("files = %#v, want only kept.example", got)
	}
}

func TestRemoveAllKeepsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Sync(dir, []string{"intra.example"}, nameserver); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corp.example"), []byte("nameserver 192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveAll(dir)
	if err != nil || !removed {
		t.Fatalf("RemoveAll() = (%v, %v), want removed", removed, err)
	}
	if got := readDir(t, dir); len(got) != 1 || got["corp.example"] == "" {
		t.Fatalf("files = %#v, want only the foreign file", got)
	}
	if removed, err := RemoveAll(filepath.Join(dir, "missing")); err != nil || removed {
		t.Fatalf("RemoveAll(missing) = (%v, %v), want no-op", removed, err)
	}
}

func TestSyncRejectsNamesOutsideDirectory(t *testing.T) {
	for _, domain := range []string{"", ".", "..", "../etc", "a/b"} {
		if _, err := Sync(t.TempDir(), []string{domain}, nameserver); err == nil {
			t.Errorf("Sync(%q) error = nil, want rejection", domain)
		}
	}
}
