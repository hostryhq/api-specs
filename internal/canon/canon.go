// Package canon holds the reference constructions of the Sync Protocol that the specs state in prose, so that the
// vectors in sync/conformance and the digests in the OpenAPI examples can be recomputed by CI (sync/protocol-v1.md:
// "Canonical JSON", "Personal data beside an op", "Projection digest"). It is test and lint support, not a runtime library;
// go-common/sync and client-core hold the production implementations and are checked against the same vectors.
package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MaxSafeInt is 2^53-1: integers beyond it are refused (money is paise, no fractions).
const MaxSafeInt = 1<<53 - 1

// JCS returns the RFC 8785 canonical JSON text of v for the integer-only subset: objects (keys in UTF-16 code unit
// order), arrays, strings, booleans, null and integers within +-(2^53-1). Fractions and exponents are refused.
func JCS(v any) ([]byte, error) {
	var sb strings.Builder
	if err := write(&sb, v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// JCSText canonicalises JSON text.
func JCSText(text string) ([]byte, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return JCS(v)
}

func write(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case string:
		writeString(sb, t)
	case int:
		return writeInt(sb, int64(t))
	case int64:
		return writeInt(sb, t)
	case float64:
		if t != math.Trunc(t) {
			return errors.New("canon: fraction refused")
		}
		return writeInt(sb, int64(t))
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return errors.New("canon: fraction or exponent refused")
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		return writeInt(sb, n)
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := write(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return less16(keys[i], keys[j]) })
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, k)
			sb.WriteByte(':')
			if err := write(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported type %T", v)
	}
	return nil
}

func writeInt(sb *strings.Builder, n int64) error {
	if n > MaxSafeInt || n < -MaxSafeInt {
		return errors.New("canon: integer outside +-(2^53-1)")
	}
	sb.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func less16(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func writeString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Commit is the per-field personal-data commitment carried in body.pii_c: lower-case hex SHA-256 over the salt bytes
// followed by the JCS text of the value. The salt is 16 random bytes kept beside the value, never in the sealed body.
func Commit(salt []byte, value any) (string, error) {
	c, err := JCS(value)
	if err != nil {
		return "", err
	}
	return sum(append(append([]byte{}, salt...), c...)), nil
}

// RowText is the canonical text of one row in the projection digest: the JCS of an object holding "id" and every field
// the row has set (absent and null fields omitted), without pii fields.
func RowText(id string, fields map[string]any, pii map[string]bool) (string, error) {
	o := map[string]any{"id": id}
	for k, v := range fields {
		if v == nil || pii[k] {
			continue
		}
		o[k] = v
	}
	b, err := JCS(o)
	return string(b), err
}

// EntityHash is the digest of one entity for a business day: SHA-256 over the row texts in ascending id order (byte
// order), each followed by a line feed. rows maps id to the canonical text.
func EntityHash(rows map[string]string) (count int, hash string) {
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var sb strings.Builder
	for _, id := range ids {
		sb.WriteString(rows[id])
		sb.WriteByte('\n')
	}
	return len(ids), sum([]byte(sb.String()))
}

// StateHash combines entity digests (entity -> {row_count, hash}): SHA-256 over "<entity>\n<row_count>\n<hash>\n" for each
// entity in ascending name order.
func StateHash(entities map[string][2]string) string {
	names := make([]string, 0, len(entities))
	for n := range entities {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString(n + "\n" + entities[n][0] + "\n" + entities[n][1] + "\n")
	}
	return sum([]byte(sb.String()))
}
