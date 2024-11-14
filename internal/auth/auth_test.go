package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type testCase struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}

	testCases := []testCase{
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header (No ApiKey prefix)",
			headers: http.Header{
				"Authorization": []string{"Bearer some-random-key"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header (No space separator)",
			headers: http.Header{
				"Authorization": []string{"ApiKeysome-random-key"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid ApiKey Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid-key"},
			},
			expectedKey:   "valid-key",
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)
			assertEqual(t, key, tc.expectedKey)
			assertErrorEqual(t, err, tc.expectedError)
		})
	}
}

func assertEqual(t *testing.T, got, expected string) {
	if got != expected {
		t.Errorf("expected key: %v, got: %v", expected, got)
	}
}

func assertErrorEqual(t *testing.T, got, expected error) {
	if (got == nil && expected != nil) || (got != nil && expected == nil) {
		t.Errorf("expected error: %v, got: %v", expected, got)
	} else if got != nil && expected != nil && got.Error() != expected.Error() {
		t.Errorf("expected error: %v, got: %v", expected, got)
	}
}
