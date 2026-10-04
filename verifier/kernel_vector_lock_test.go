package verifier_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Fixture suites vendored from actenon-kernel whose files the kernel's hash
// lock (conformance/vector-lock.json) covers, keyed by fixtures/ directory,
// with the matching directory in the kernel repository.
var lockedKernelSuites = map[string]string{
	"receipt_countersignature_v1": "conformance/vectors/receipt_countersignature_v1",
	"transparency_log_v1":         "conformance/vectors/transparency_log_v1",
	"trust_artifacts_v1":          "conformance/vectors/trust_artifacts_v1",
	"verifier_sdk_v1":             "actenon/conformance/vectors/verifier_sdk_v1",
}

// kernelVectorLockEnv names a kernel vector-lock.json to check against
// instead of the vendored copy; CI sets it to the lock downloaded from the
// kernel at fixtures/KERNEL_PIN.
const kernelVectorLockEnv = "ACTENON_KERNEL_VECTOR_LOCK"

type kernelVectorLock struct {
	Algorithm     string            `json:"algorithm"`
	SchemaVersion int               `json:"schema_version"`
	Files         map[string]string `json:"files"`
}

func fixturesRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "fixtures")
}

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixturesRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("failed to read fixtures/%s: %v", rel, err)
	}
	return raw
}

// readKernelUnlocked parses fixtures/KERNEL_UNLOCKED into
// fixtures-relative path -> kernel path.
func readKernelUnlocked(t *testing.T) map[string]string {
	t.Helper()
	unlocked := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(readFixture(t, "KERNEL_UNLOCKED")))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed KERNEL_UNLOCKED line: %q", line)
		}
		unlocked[fields[0]] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to read KERNEL_UNLOCKED: %v", err)
	}
	return unlocked
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Every vendored kernel fixture must be byte-identical to what the kernel's
// hash lock records at fixtures/KERNEL_PIN; every file the lock records for a
// vendored suite must be vendored; and any other file in a vendored kernel
// suite must be listed in KERNEL_UNLOCKED (and must really be unlocked).
func TestVendoredKernelVectorsMatchKernelLock(t *testing.T) {
	pin := strings.TrimSpace(string(readFixture(t, "KERNEL_PIN")))
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pin) {
		t.Fatalf("fixtures/KERNEL_PIN must be a full 40-hex commit SHA, got %q", pin)
	}

	vendoredLock := readFixture(t, "kernel_vector_lock.json")
	lockRaw := vendoredLock
	if path := os.Getenv(kernelVectorLockEnv); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s=%s: %v", kernelVectorLockEnv, path, err)
		}
		if !bytes.Equal(raw, vendoredLock) {
			t.Fatalf("fixtures/kernel_vector_lock.json differs from %s (kernel lock at %s)", path, pin)
		}
		lockRaw = raw
	}
	var lock kernelVectorLock
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		t.Fatalf("failed to decode kernel vector lock: %v", err)
	}
	if lock.Algorithm != "sha256" || lock.SchemaVersion != 1 || len(lock.Files) == 0 {
		t.Fatalf("unexpected kernel vector lock: algorithm=%q schema_version=%d files=%d",
			lock.Algorithm, lock.SchemaVersion, len(lock.Files))
	}

	covered := map[string]bool{}
	for _, kernelPath := range sortedKeys(lock.Files) {
		for _, suite := range sortedKeys(lockedKernelSuites) {
			prefix := lockedKernelSuites[suite] + "/"
			if !strings.HasPrefix(kernelPath, prefix) {
				continue
			}
			rel := suite + "/" + strings.TrimPrefix(kernelPath, prefix)
			covered[rel] = true
			raw, err := os.ReadFile(filepath.Join(fixturesRoot(t), filepath.FromSlash(rel)))
			if err != nil {
				t.Errorf("fixtures/%s is missing: the kernel lock at %s records %s", rel, pin, kernelPath)
				continue
			}
			digest := sha256.Sum256(raw)
			if got := hex.EncodeToString(digest[:]); got != lock.Files[kernelPath] {
				t.Errorf("fixtures/%s sha256 %s, kernel lock at %s records %s for %s",
					rel, got, pin, lock.Files[kernelPath], kernelPath)
			}
		}
	}

	unlocked := readKernelUnlocked(t)
	suites := map[string]bool{}
	for suite := range lockedKernelSuites {
		suites[suite] = true
	}
	for _, rel := range sortedKeys(unlocked) {
		if _, locked := lock.Files[unlocked[rel]]; locked {
			t.Errorf("%s is hash-locked by the kernel at %s; remove fixtures/%s from KERNEL_UNLOCKED",
				unlocked[rel], pin, rel)
		}
		if _, err := os.Stat(filepath.Join(fixturesRoot(t), filepath.FromSlash(rel))); err != nil {
			t.Errorf("KERNEL_UNLOCKED lists fixtures/%s, which is missing", rel)
		}
		covered[rel] = true
		suites[strings.SplitN(rel, "/", 2)[0]] = true
	}

	for _, suite := range sortedKeys(suites) {
		suiteRoot := filepath.Join(fixturesRoot(t), suite)
		err := filepath.WalkDir(suiteRoot, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			rel, err := filepath.Rel(fixturesRoot(t), path)
			if err != nil {
				return err
			}
			if rel = filepath.ToSlash(rel); !covered[rel] {
				t.Errorf("fixtures/%s is neither in the kernel lock at %s nor in KERNEL_UNLOCKED", rel, pin)
			}
			return nil
		})
		if err != nil {
			t.Errorf("failed to walk fixtures/%s: %v", suite, err)
		}
	}
}
