package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	emptyHeader := make(http.Header)

	malformedHeader := make(http.Header)
	malformedHeader.Add("Authorization", "NotApiKey 1234")

	goodHeader := make(http.Header)
	goodHeader.Add("Authorization", "ApiKey 1234")

	key, err := GetAPIKey(emptyHeader)
	if key != "" || err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected empty key and ErrNoAuthHeaderIncluded, got '%s' key and '%v' error\n", key, err)
	}

	key, err = GetAPIKey(malformedHeader)
	if key != "" || err.Error() != "malformed authorization header" {
		t.Fatalf("expected empty key and 'malformed authorization header' error, got '%s' key and '%v' error\n", key, err)
	}

	key, err = GetAPIKey(goodHeader)
	if key != "1234" || err != nil {
		t.Fatalf("expected '1234' key and nil error, got '%s' key and '%v' error\n", key, err)
	}
}
