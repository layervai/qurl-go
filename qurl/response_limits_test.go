package qurl

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestResponseBodyLimitOptions(t *testing.T) {
	if maxAPIResponseBodyBytes != 1<<20 || maxConfigurableAPIResponseBodyBytes != 16<<20 {
		t.Fatal("joint SDK response policy drifted")
	}
	for _, limit := range []int{0, -1, (16 << 20) + 1} {
		if _, err := NewClient(BearerToken("lv_test"), WithMaxResponseBodyBytes(limit)); !errors.Is(err, ErrInvalidClientConfig) {
			t.Fatalf("limit=%d error=%v", limit, err)
		}
		cfg := nativeAgentRuntimeConfig{}
		if err := WithMaxResponseBodyBytes(limit).applyAgentRuntimeOption(&cfg); !errors.Is(err, ErrInvalidRegisterConfig) {
			t.Fatalf("native limit=%d error=%v", limit, err)
		}
	}
	for _, limit := range []int{1, 1 << 20, 16 << 20} {
		client, err := NewClient(BearerToken("lv_test"), WithMaxResponseBodyBytes(limit))
		if err != nil || client.maxResponseBodyBytes != limit {
			t.Fatalf("limit=%d client=%+v error=%v", limit, client, err)
		}
		cfg := nativeAgentRuntimeConfig{}
		if err := WithMaxResponseBodyBytes(limit).applyAgentRuntimeOption(&cfg); err != nil || cfg.maxResponseBodyBytes != limit {
			t.Fatalf("native limit=%d config=%+v error=%v", limit, cfg, err)
		}
	}
}

func responseBodyAtSize(size int) string {
	const prefix = `{"data":{"padding":"`
	const suffix = `"}}`
	alphabet := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	padding := size - len(prefix) - len(suffix)
	return prefix + strings.Repeat(alphabet, padding/len(alphabet)+1)[:padding] + suffix
}

func TestConfiguredResponseLimitCountsBytes(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, header := range []string{"", "1", "512"} {
			for _, size := range []int{512, 513} {
				t.Run(fmt.Sprintf("%s/header=%s/size=%d", method, header, size), func(t *testing.T) {
					calls := 0
					client, err := NewClient(BearerToken("lv_test"), WithMaxResponseBodyBytes(512), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
						calls++
						headers := make(http.Header)
						if header != "" {
							headers.Set("Content-Length", header)
						}
						return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader(responseBodyAtSize(size)))}, nil
					})))
					if err != nil {
						t.Fatal(err)
					}
					var out map[string]any
					if method == http.MethodPost {
						err = client.postJSON(context.Background(), "/v1/test", nil, &out)
					} else {
						err = client.doJSONStatus(context.Background(), method, "/v1/test", nil, &out, 200)
					}
					if size == 512 {
						if err != nil {
							t.Fatal(err)
						}
					} else {
						var capError *inputExceedsCapError
						if !errors.Is(err, ErrInvalidAPIResponse) || !errors.As(err, &capError) || capError.limit != 512 {
							t.Fatalf("cap error=%v", err)
						}
					}
					if calls != 1 {
						t.Fatalf("calls=%d", calls)
					}
				})
			}
		}
	}
}

func TestRegisteredClientResponseLimit(t *testing.T) {
	store := &memoryAgentStateStore{state: completedNativeTestState(t)}
	client, err := OpenRegisteredAgent(context.Background(), store, WithMaxResponseBodyBytes(128), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(responseBodyAtSize(129)))}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err = client.postJSON(context.Background(), "/v1/test", nil, &out)
	var capError *inputExceedsCapError
	if !errors.As(err, &capError) || capError.limit != 128 {
		t.Fatalf("registered Client lost cap: %v", err)
	}
}

func TestConfiguredLimitCountsDecompressedBytes(t *testing.T) {
	for _, size := range []int{64, 65} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var compressed bytes.Buffer
			writer := gzip.NewWriter(&compressed)
			if _, err := io.WriteString(writer, responseBodyAtSize(size)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if compressed.Len() <= 64 {
				t.Fatalf("gzip fixture did not exceed the decoded cap: %d", compressed.Len())
			}
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Length", fmt.Sprint(compressed.Len()))
				_, _ = w.Write(compressed.Bytes())
			}))
			defer api.Close()
			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL), WithMaxResponseBodyBytes(64))
			if err != nil {
				t.Fatal(err)
			}
			var out map[string]any
			err = client.doJSONStatus(context.Background(), http.MethodGet, "/v1/test", nil, &out, 200)
			if size == 64 {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var capError *inputExceedsCapError
				if !errors.As(err, &capError) {
					t.Fatalf("decoded body escaped cap: %v", err)
				}
			}
		})
	}
}

// These are the public request-contract maxima: 100 rows, 2048-byte URL,
// 500-byte description, ten distinct 50-byte tags and 256 device keys/passkeys.
// Passkey names reach their published 64-byte maximum. Go's normal JSON
// escaping expands '&' and '<' beyond the unchanged 1 MiB default.
func maximumResourcePage(t *testing.T) []byte {
	t.Helper()
	prefix := "https://example.com/?q="
	target := prefix + strings.Repeat("&", 2048-len(prefix))
	description := strings.Repeat("<", 500)
	tags := make([]string, 10)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag-%d%s", i, strings.Repeat("a", 45))
	}
	deviceKeys := make([]string, 256)
	passkeys := make([]map[string]any, 256)
	encoding := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	for i := range deviceKeys {
		digest := sha256.Sum256([]byte(fmt.Sprintf("response-limit-device-%d", i)))
		deviceKeys[i] = base64.StdEncoding.EncodeToString(digest[:])
		id := encoding.EncodeToString(digest[:])[:16]
		passkeys[i] = map[string]any{"device_id": id[:4] + "-" + id[4:8] + "-" + id[8:12] + "-" + id[12:], "name": strings.Repeat("<", 64), "approved_at": "2026-10-31T00:00:00Z"}
	}
	rows := make([]map[string]any, 100)
	for i := range rows {
		scalar := make([]byte, 32)
		scalar[31] = byte(i + 1)
		key, err := ecdh.P256().NewPrivateKey(scalar)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(key.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = map[string]any{"resource_id": base64.RawURLEncoding.EncodeToString(der), "crid": testCRIDForKey(1, 32, der), "type": "url", "status": "active", "target_url": target, "description": description, "tags": tags, "private": true, "allowed_device_keys": deviceKeys, "allowed_passkeys": passkeys, "consumer_access": map[string]any{"mode": "keys", "version": 1}, "created_at": "2026-10-31T00:00:00Z"}
	}
	raw, err := json.Marshal(map[string]any{"data": rows, "meta": map[string]any{"page_size": 100, "has_more": false}})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= maxAPIResponseBodyBytes || len(raw) > 16<<20 {
		t.Fatalf("boundary page bytes=%d", len(raw))
	}
	if len(raw) != 14771352 {
		t.Fatalf("shared large-page fixture drifted: %d bytes", len(raw))
	}
	t.Logf("maximum documented-field page: %d decoded JSON bytes", len(raw))
	return raw
}

func TestMaximumResourcePageWithBoundedOptIn(t *testing.T) {
	raw := maximumResourcePage(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer api.Close()
	for _, limit := range []int{0, 16 << 20} {
		options := []ClientOption{WithBaseURL(api.URL)}
		if limit != 0 {
			options = append(options, WithMaxResponseBodyBytes(limit))
		}
		client, err := NewClient(BearerToken("lv_test"), options...)
		if err != nil {
			t.Fatal(err)
		}
		page, err := client.ListResources(context.Background(), ResourceListOptions{Limit: 100})
		if limit == 0 {
			if !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatalf("default cap: %v", err)
			}
		} else if err != nil || len(page.Data) != 100 {
			t.Fatalf("bounded maximum page: rows=%v error=%v", page, err)
		}
	}
}

type responseLimitReadTracker struct {
	reader io.Reader
	reads  int
	closed bool
}

func (b *responseLimitReadTracker) Read(p []byte) (int, error) { b.reads++; return b.reader.Read(p) }
func (b *responseLimitReadTracker) Close() error               { b.closed = true; return nil }

func TestResponseLimitHeaderHints(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lengths  []string
		encoding string
		tooLarge bool
	}{
		{"missing", nil, "", false},
		{"false-small", []string{"1"}, "", false},
		{"oversized", []string{"1024"}, "", true},
		{"overflow", []string{"999999999999999999999999"}, "", true},
		{"malformed", []string{"invalid"}, "", false},
		{"duplicate", []string{"1024", "1"}, "", false},
		{"gzip decoded", []string{"1024"}, "gzip", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &responseLimitReadTracker{reader: strings.NewReader(responseBodyAtSize(64))}
			headers := make(http.Header)
			headers["Content-Length"] = tc.lengths
			if tc.encoding != "" {
				headers.Set("Content-Encoding", tc.encoding)
			}
			client, err := NewClient(BearerToken("lv_test"), WithMaxResponseBodyBytes(128), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: body}, nil
			})))
			if err != nil {
				t.Fatal(err)
			}
			var out map[string]any
			err = client.doJSONStatus(context.Background(), http.MethodGet, "/v1/test", nil, &out, 200)
			if tc.tooLarge {
				var capError *inputExceedsCapError
				if !errors.As(err, &capError) || !errors.Is(err, ErrInvalidAPIResponse) || body.reads != 0 {
					t.Fatalf("hint error=%v reads=%d", err, body.reads)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
		})
	}
	for _, status := range []int{204, 205, 304} {
		if apiContentLengthExceedsLimit(&http.Response{StatusCode: status, Header: http.Header{"Content-Length": []string{"1024"}}}, 128) {
			t.Fatalf("bodyless status %d used a body-size hint", status)
		}
	}
}

func TestResponseLimitPreservesHTTPErrorClass(t *testing.T) {
	for _, status := range []int{429, 503} {
		client, err := NewClient(BearerToken("lv_test"), WithMaxResponseBodyBytes(128), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(responseBodyAtSize(129)))}, nil
		})))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		err = client.doJSONStatus(context.Background(), http.MethodGet, "/v1/test", nil, &out, 200)
		var apiError *APIError
		var capError *inputExceedsCapError
		if !errors.As(err, &apiError) || apiError.StatusCode != status || !errors.As(err, &capError) {
			t.Fatalf("status=%d error=%v", status, err)
		}
	}
}

func TestResponseLimitCursorRecovery(t *testing.T) {
	raw := maximumResourcePage(t)
	var whole struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &whole); err != nil {
		t.Fatal(err)
	}
	type call struct{ cursor, limit string }
	var calls []call
	var callsMu sync.Mutex
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("status") != "active" || q.Get("type") != "url" {
			t.Errorf("filters changed: %s", r.URL.RawQuery)
		}
		callsMu.Lock()
		calls = append(calls, call{q.Get("cursor"), q.Get("limit")})
		callsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if q.Get("cursor") == "" {
			if err := json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"resource_id": testConnectorID, "crid": testConnectorCRID}}, "meta": map[string]any{"has_more": true, "next_cursor": "saved", "page_size": 1}}); err != nil {
				t.Error(err)
			}
			return
		}
		if q.Get("cursor") != "saved" {
			t.Errorf("advanced failed cursor: %s", q.Get("cursor"))
		}
		if q.Get("limit") == "100" {
			_, _ = w.Write(raw)
			return
		}
		if q.Get("limit") != "5" {
			t.Errorf("retry limit=%s", q.Get("limit"))
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"data": whole.Data[:5], "meta": map[string]any{"has_more": true, "next_cursor": "after-five", "page_size": 5}}); err != nil {
			t.Error(err)
		}
	}))
	defer api.Close()
	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatal(err)
	}
	options := ResourceListOptions{Limit: 100, Status: []string{"active"}, Type: "url"}
	first, err := client.ListResources(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	options.Cursor = first.Meta.NextCursor
	if _, err = client.ListResources(context.Background(), options); !errors.Is(err, ErrInvalidAPIResponse) {
		t.Fatalf("oversized next page: %v", err)
	}
	options.Limit = 5
	page, err := client.ListResources(context.Background(), options)
	if err != nil || len(page.Data) != 5 || page.Meta.NextCursor != "after-five" {
		t.Fatalf("cursor recovery: page=%v error=%v", page, err)
	}
	want := []call{{"", "100"}, {"saved", "100"}, {"saved", "5"}}
	callsMu.Lock()
	defer callsMu.Unlock()
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("requests=%v want=%v", calls, want)
	}
}
