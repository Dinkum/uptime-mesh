package main

import "testing"

func TestHeartbeatSigningMessageCanonicalJSON(t *testing.T) {
	message, err := heartbeatSigningMessage(
		"node-a",
		"lease-token",
		1700000000,
		45,
		map[string]any{
			"z": "<tag>&value",
			"a": map[string]any{"nested": true},
		},
	)
	if err != nil {
		t.Fatalf("heartbeatSigningMessage returned error: %v", err)
	}

	expected := "node-a\nlease-token\n1700000000\n45\n{\"a\":{\"nested\":true},\"z\":\"<tag>&value\"}"
	if string(message) != expected {
		t.Fatalf("unexpected signing message:\n%s", string(message))
	}
}
