package nativeudp_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

const (
	typedEvidencePathEnv  = "QURL_GO_SANDBOX_TYPED_EVIDENCE_PATH"
	typedEvidenceMaxBytes = 1024 * 1024
	typedEvidenceProducer = "layervai/qurl-go"
)

var (
	typedEvidenceMu         sync.Mutex
	typedEvidenceNameRegexp = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	typedEvidenceTestRegexp = regexp.MustCompile(`^Test[A-Za-z0-9_]+(?:/[a-z0-9_]+)*$`)
)

type successfulTypedEvidenceObservation struct {
	EvidenceKind string `json:"evidence_kind"`
	Outcome      string `json:"outcome"`
	Producer     string `json:"producer"`
	ScenarioKey  string `json:"scenario_key"`
	TestName     string `json:"test_name"`
	Verified     bool   `json:"verified"`
}

type successfulTypedEvidenceRecord struct {
	Kind              string          `json:"kind"`
	Observation       json.RawMessage `json:"observation"`
	ObservationSHA256 string          `json:"observation_sha256"`
	ScenarioKey       string          `json:"scenario_key"`
}

type nhpTypedEvidenceObservation struct {
	EvidenceKind  string `json:"evidence_kind"`
	Producer      string `json:"producer"`
	ProducerRunID int64  `json:"producer_run_id"`
	RowSHA256     string `json:"row_sha256"`
	ScenarioKey   string `json:"scenario_key"`
	SourceSHA     string `json:"source_sha"`
	Verified      bool   `json:"verified"`
}

type nhpTypedEvidenceBinding struct {
	ProducerRunID int64
	RowSHA256     string
	SourceSHA     string
}

// runTypedEvidenceScenario appends evidence only from the cleanup of a named
// subtest that actually passed. Registering this cleanup before the body makes
// it run after every cleanup installed by the scenario itself, so a cleanup
// failure, skip, fatal, or panic cannot produce a success record.
func runTypedEvidenceScenario(
	t *testing.T,
	testName string,
	scenarioKey string,
	kinds []string,
	body func(*testing.T),
) bool {
	t.Helper()
	return t.Run(testName, func(t *testing.T) {
		t.Cleanup(func() {
			if t.Failed() || t.Skipped() {
				return
			}
			if err := appendSuccessfulTypedEvidence(
				os.Getenv(typedEvidencePathEnv), scenarioKey, t.Name(), kinds,
			); err != nil {
				t.Errorf("append typed evidence for %s: %v", scenarioKey, err)
			}
		})
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					// testing does not mark a subtest failed until after panic
					// unwinding. Mark it before cleanup so the producer cannot
					// publish a false success, then preserve the panic.
					t.Errorf("typed-evidence scenario panicked: %v", recovered)
					panic(recovered)
				}
			}()
			body(t)
		}()
	})
}

func appendSuccessfulTypedEvidence(path, scenarioKey, testName string, kinds []string) error {
	return appendBoundTypedEvidence(path, scenarioKey, testName, kinds, nil)
}

func appendNHPOrchestratorTypedEvidence(
	path, scenarioKey string,
	kind string,
	binding nhpTypedEvidenceBinding,
) error {
	return appendBoundTypedEvidence(path, scenarioKey, "", []string{kind}, &binding)
}

func appendBoundTypedEvidence(
	path, scenarioKey, testName string,
	kinds []string,
	nhpBinding *nhpTypedEvidenceBinding,
) error {
	typedEvidenceMu.Lock()
	defer typedEvidenceMu.Unlock()

	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be one canonical absolute path", typedEvidencePathEnv)
	}
	if !typedEvidenceNameRegexp.MatchString(scenarioKey) {
		return fmt.Errorf("invalid typed evidence scenario key %q", scenarioKey)
	}
	if nhpBinding == nil && !typedEvidenceTestRegexp.MatchString(testName) {
		return fmt.Errorf("invalid typed evidence test name %q", testName)
	}
	if nhpBinding != nil &&
		(nhpBinding.ProducerRunID < 1 ||
			!canonicalLowerHex(nhpBinding.RowSHA256, sha256.Size*2) ||
			!canonicalLowerHex(nhpBinding.SourceSHA, 40)) {
		return errors.New("invalid NHP typed evidence binding")
	}
	if len(kinds) == 0 || !sort.StringsAreSorted(kinds) {
		return errors.New("typed evidence kinds must be a nonempty sorted list")
	}

	existing := make(map[string]struct{})
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("typed evidence path must be a regular non-symlink file")
		}
		if info.Size() > typedEvidenceMaxBytes {
			return errors.New("typed evidence file exceeds its byte limit")
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read typed evidence: %w", readErr)
		}
		if err := collectExistingTypedEvidence(raw, existing); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect typed evidence path: %w", err)
	}

	var payload bytes.Buffer
	seenKinds := make(map[string]struct{}, len(kinds))
	for _, kind := range kinds {
		if !typedEvidenceNameRegexp.MatchString(kind) {
			return fmt.Errorf("invalid typed evidence kind %q", kind)
		}
		if _, duplicate := seenKinds[kind]; duplicate {
			return fmt.Errorf("duplicate typed evidence kind %q for %s", kind, scenarioKey)
		}
		seenKinds[kind] = struct{}{}
		identity := scenarioKey + "\x00" + kind
		if _, duplicate := existing[identity]; duplicate {
			return fmt.Errorf("duplicate typed evidence kind %q for %s", kind, scenarioKey)
		}
		var observation any
		if nhpBinding == nil {
			observation = successfulTypedEvidenceObservation{
				EvidenceKind: kind,
				Outcome:      "pass",
				Producer:     typedEvidenceProducer,
				ScenarioKey:  scenarioKey,
				TestName:     testName,
				Verified:     true,
			}
		} else {
			observation = nhpTypedEvidenceObservation{
				EvidenceKind:  kind,
				Producer:      orchestratorProofRepository,
				ProducerRunID: nhpBinding.ProducerRunID,
				RowSHA256:     nhpBinding.RowSHA256,
				ScenarioKey:   scenarioKey,
				SourceSHA:     nhpBinding.SourceSHA,
				Verified:      true,
			}
		}
		observationRaw, err := json.Marshal(observation)
		if err != nil {
			return fmt.Errorf("marshal typed evidence observation: %w", err)
		}
		observationDigest := sha256.Sum256(observationRaw)
		record := successfulTypedEvidenceRecord{
			Kind:              kind,
			Observation:       observationRaw,
			ObservationSHA256: hex.EncodeToString(observationDigest[:]),
			ScenarioKey:       scenarioKey,
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal typed evidence: %w", err)
		}
		payload.Write(encoded)
		payload.WriteByte('\n')
	}
	if payload.Len() == 0 || payload.Len() > typedEvidenceMaxBytes {
		return errors.New("typed evidence append exceeds its byte limit")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open typed evidence: %w", err)
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr != nil {
		return fmt.Errorf("inspect opened typed evidence: %w", statErr)
	} else if !info.Mode().IsRegular() || info.Size()+int64(payload.Len()) > typedEvidenceMaxBytes {
		return errors.New("opened typed evidence path is invalid or exceeds its byte limit")
	}
	if written, err := file.Write(payload.Bytes()); err != nil {
		return fmt.Errorf("append typed evidence: %w", err)
	} else if written != payload.Len() {
		return io.ErrShortWrite
	}
	return nil
}

func collectExistingTypedEvidence(raw []byte, identities map[string]struct{}) error {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 16*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(line) == 0 {
			return fmt.Errorf("typed evidence line %d is empty", lineNumber)
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var record successfulTypedEvidenceRecord
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("decode typed evidence line %d: %w", lineNumber, err)
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return fmt.Errorf("typed evidence line %d has trailing JSON", lineNumber)
		}
		canonical, err := json.Marshal(record)
		if err != nil || !bytes.Equal(canonical, line) {
			return fmt.Errorf("typed evidence line %d is not canonical", lineNumber)
		}
		observationDigest := sha256.Sum256(record.Observation)
		if record.ObservationSHA256 != hex.EncodeToString(observationDigest[:]) ||
			!typedEvidenceNameRegexp.MatchString(record.ScenarioKey) ||
			!typedEvidenceNameRegexp.MatchString(record.Kind) {
			return fmt.Errorf("typed evidence line %d is not an exact success record", lineNumber)
		}
		var header struct {
			Producer string `json:"producer"`
		}
		if err := json.Unmarshal(record.Observation, &header); err != nil {
			return fmt.Errorf("decode typed evidence line %d observation header: %w", lineNumber, err)
		}
		switch header.Producer {
		case typedEvidenceProducer:
			observation, err := decodeStrictJSON[successfulTypedEvidenceObservation](
				record.Observation, "qurl-go typed evidence observation",
			)
			if err != nil ||
				!observation.Verified ||
				observation.Outcome != "pass" ||
				observation.ScenarioKey != record.ScenarioKey ||
				observation.EvidenceKind != record.Kind ||
				!typedEvidenceTestRegexp.MatchString(observation.TestName) {
				return fmt.Errorf("typed evidence line %d is not a bound qurl-go success record", lineNumber)
			}
		case orchestratorProofRepository:
			observation, err := decodeStrictJSON[nhpTypedEvidenceObservation](
				record.Observation, "NHP typed evidence observation",
			)
			if err != nil ||
				!observation.Verified ||
				observation.ProducerRunID < 1 ||
				observation.ScenarioKey != record.ScenarioKey ||
				observation.EvidenceKind != record.Kind ||
				!canonicalLowerHex(observation.RowSHA256, sha256.Size*2) ||
				!canonicalLowerHex(observation.SourceSHA, 40) {
				return fmt.Errorf("typed evidence line %d is not a bound NHP success record", lineNumber)
			}
		default:
			return fmt.Errorf("typed evidence line %d has an unknown producer", lineNumber)
		}
		identity := record.ScenarioKey + "\x00" + record.Kind
		if _, duplicate := identities[identity]; duplicate {
			return fmt.Errorf("typed evidence line %d is a duplicate", lineNumber)
		}
		identities[identity] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan typed evidence: %w", err)
	}
	return nil
}

func TestTypedEvidenceScenarioProducerSubprocess(t *testing.T) {
	mode := os.Getenv("QURL_GO_TYPED_EVIDENCE_SUBPROCESS")
	if mode == "" {
		return
	}
	run := func(t *testing.T) {
		switch mode {
		case "success", "duplicate":
		case "skip":
			t.Skip("intentional producer proof skip")
		case "failure":
			t.Fatal("intentional producer proof failure")
		case "panic":
			panic("intentional producer proof panic")
		default:
			t.Fatalf("unknown subprocess mode %q", mode)
		}
	}
	runTypedEvidenceScenario(t, "scenario", "proof.success-only", []string{"wire_trace"}, run)
	if mode == "duplicate" {
		runTypedEvidenceScenario(t, "duplicate", "proof.success-only", []string{"wire_trace"}, run)
	}
}

func TestTypedEvidenceScenarioProducerEmitsOnlyAfterSuccess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "skip", "failure", "panic", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observations.jsonl")
			command := exec.CommandContext(t.Context(), executable, "-test.run=^TestTypedEvidenceScenarioProducerSubprocess$")
			command.Env = append(os.Environ(),
				"QURL_GO_TYPED_EVIDENCE_SUBPROCESS="+mode,
				typedEvidencePathEnv+"="+path,
			)
			output, runErr := command.CombinedOutput()
			if mode == "success" || mode == "skip" {
				if runErr != nil {
					t.Fatalf("%s subprocess failed: %v: %s", mode, runErr, output)
				}
			} else if runErr == nil {
				t.Fatalf("%s subprocess unexpectedly passed: %s", mode, output)
			}
			raw, readErr := os.ReadFile(path)
			if mode == "skip" || mode == "failure" || mode == "panic" {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("%s produced false evidence: %q, err=%v", mode, raw, readErr)
				}
				return
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("%s wrote %d records, want exactly one: %q", mode, len(lines), raw)
			}
			observation := `{"evidence_kind":"wire_trace","outcome":"pass","producer":"layervai/qurl-go","scenario_key":"proof.success-only","test_name":"TestTypedEvidenceScenarioProducerSubprocess/scenario","verified":true}`
			digest := sha256.Sum256([]byte(observation))
			want := `{"kind":"wire_trace","observation":` + observation + `,"observation_sha256":"` + hex.EncodeToString(digest[:]) + `","scenario_key":"proof.success-only"}`
			if lines[0] != want {
				t.Fatalf("noncanonical success evidence: got %q, want %q", lines[0], want)
			}
		})
	}
}
