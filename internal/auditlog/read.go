package auditlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Query filters what List returns. A zero Query matches everything.
type Query struct {
	Root    string    // synced root path; "" means every root's log
	Session string    // exact session id
	Path    string    // case-sensitive substring of RelPath or OldRelPath
	Since   time.Time // records at or after this instant
}

// Roots reads the "<key>.root" sidecars in dir and returns key -> absolute
// root path for every audit log present. A missing dir is not an error — it
// just means nothing has been logged yet.
func Roots(dir string) (map[string]string, error) {
	sidecars, err := filepath.Glob(filepath.Join(dir, "*.root"))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(sidecars))
	for _, s := range sidecars {
		key := strings.TrimSuffix(filepath.Base(s), ".root")
		data, readErr := os.ReadFile(s)
		if readErr != nil {
			continue
		}
		out[key] = strings.TrimSpace(string(data))
	}
	return out, nil
}

// List reads the matching log files (the live "<key>.jsonl" plus its
// rotated "<key>.jsonl.1", if any), parses every line, applies q, and
// returns the survivors sorted by time then OpID. Unparseable lines are
// skipped rather than failing the whole read — a torn last line from a
// crash mid-write must not make the log unreadable.
func List(dir string, q Query) ([]Record, error) {
	var stems []string
	if q.Root != "" {
		stems = []string{rootKey(q.Root)}
	} else {
		live, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		if err != nil {
			return nil, err
		}
		for _, p := range live {
			stems = append(stems, strings.TrimSuffix(filepath.Base(p), ".jsonl"))
		}
	}

	var recs []Record
	for _, stem := range stems {
		base := filepath.Join(dir, stem+".jsonl")
		for _, path := range generations(base) {
			fileRecs, err := readFile(path)
			if err != nil {
				return nil, err
			}
			for _, r := range fileRecs {
				if matches(r, q) {
					recs = append(recs, r)
				}
			}
		}
	}

	sort.Slice(recs, func(i, j int) bool {
		if recs[i].Time.Equal(recs[j].Time) {
			return recs[i].OpID < recs[j].OpID
		}
		return recs[i].Time.Before(recs[j].Time)
	})
	return recs, nil
}

// generations lists a log's files oldest-first: the rotated backups from
// "<base>.<maxBackups>" down to "<base>.1", then the live "<base>". Reading
// in this order keeps the merge roughly chronological before List's sort.
func generations(base string) []string {
	out := make([]string, 0, maxBackups+1)
	for n := maxBackups; n >= 1; n-- {
		out = append(out, fmt.Sprintf("%s.%d", base, n))
	}
	return append(out, base)
}

func readFile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			continue // torn or partial line — skip it
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func matches(r Record, q Query) bool {
	if q.Session != "" && r.Session != q.Session {
		return false
	}
	if q.Path != "" && !strings.Contains(r.RelPath, q.Path) && !strings.Contains(r.OldRelPath, q.Path) {
		return false
	}
	if !q.Since.IsZero() && r.Time.Before(q.Since) {
		return false
	}
	return true
}
