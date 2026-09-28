package basispoints

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

const terminalErrorPayload = `{"type":"error","sequence_number":2,"error":{"type":"tokens","code":"rate_limit_exceeded","message":"Rate limit reached for gpt-6-sol: Please try again in 34ms."}}`

func terminalWire(parts ...string) string { return strings.Join(parts, "") }

// The Excel gateway opens a failure with a bare `error` frame and then sends the
// authoritative `response.failed`. The bridge must keep reading so the terminal
// frame reaches the client instead of a silent EOF ("stream closed before
// response.completed").
func TestBareErrorFrameKeepsReadingUntilTheTerminalEvent(t *testing.T) {
	_, bridge := mustPrepare(t, testSource(), "", nil)
	wire := terminalWire(
		sse(object{"type": "response.created", "response": object{"id": "resp_limit"}}),
		"event: error\ndata: "+terminalErrorPayload+"\n\n",
		sse(object{"type": "response.failed", "response": object{"id": "resp_limit", "output": []any{}, "error": object{"code": "rate_limit_exceeded"}}}),
	)
	body := bridge.Stream(io.NopCloser(strings.NewReader(wire)))
	defer func() { _ = body.Close() }()
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("terminal frame must not be reported as a stream failure: %v", err)
	}
	if !bytes.Contains(out, []byte("response.failed")) {
		t.Fatalf("terminal frame missing from bridge output: %s", out)
	}
	if bytes.Contains(out, []byte("event: error\n")) {
		t.Fatalf("bare error frame must not be forwarded once a terminal frame exists: %s", out)
	}
	if payload := bridge.LastErrorPayload(); !bytes.Contains(payload, []byte("rate_limit_exceeded")) {
		t.Fatalf("captured error payload lost its code: %s", payload)
	}
}

// Upstream closing right after the bare frame still ends the stream (the caller
// synthesizes the terminal event), but the payload must survive so the client can
// be told which upstream error actually happened.
func TestBareErrorFrameWithoutTerminalIsCapturedForTheCaller(t *testing.T) {
	_, bridge := mustPrepare(t, testSource(), "", nil)
	wire := terminalWire(
		sse(object{"type": "response.created", "response": object{"id": "resp_limit"}}),
		"event: error\ndata: "+terminalErrorPayload+"\n\n",
	)
	body := bridge.Stream(io.NopCloser(strings.NewReader(wire)))
	defer func() { _ = body.Close() }()
	out, err := io.ReadAll(body)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected an incomplete stream, got %v", err)
	}
	if bytes.Contains(out, []byte("event: error\n")) {
		t.Fatalf("bare error frame must not be forwarded: %s", out)
	}
	if payload := bridge.LastErrorPayload(); !bytes.Contains(payload, []byte("Please try again in 34ms")) {
		t.Fatalf("captured error payload lost its message: %s", payload)
	}
}

func TestStreamsWithoutBareErrorFramesCaptureNothing(t *testing.T) {
	_, bridge := mustPrepare(t, testSource(), "", nil)
	wire := sse(object{"type": "response.completed", "response": object{"id": "resp_ok", "output": []any{}}})
	body := bridge.Stream(io.NopCloser(strings.NewReader(wire)))
	defer func() { _ = body.Close() }()
	if _, err := io.ReadAll(body); err != nil {
		t.Fatal(err)
	}
	if payload := bridge.LastErrorPayload(); len(payload) != 0 {
		t.Fatalf("unexpected captured error payload: %s", payload)
	}
}
