package auth

import (
	"testing"
	"time"
)

func TestAuthenticate(t *testing.T) {
	svc := New("admin", "correct horse", true, time.Hour)
	if !svc.Authenticate("admin", "correct horse") {
		t.Fatal("valid credentials rejected")
	}
	if svc.Authenticate("admin", "wrong") {
		t.Fatal("invalid password accepted")
	}
	if svc.Authenticate("root", "correct horse") {
		t.Fatal("invalid username accepted")
	}
}

func TestSessions(t *testing.T) {
	svc := New("admin", "password", true, time.Hour)
	now := time.Unix(1000, 0)
	svc.now = func() time.Time { return now }

	token, expires := svc.CreateSession("admin")
	if token == "" || !expires.After(now) {
		t.Fatalf("bad session: token=%q expires=%v", token, expires)
	}
	if sess, ok := svc.Session(token); !ok || sess.User != "admin" {
		t.Fatalf("session lookup failed: %+v %v", sess, ok)
	}
	if !svc.Valid(token) {
		t.Fatal("token should be valid")
	}
	svc.DeleteSession(token)
	if svc.Valid(token) {
		t.Fatal("deleted token still valid")
	}

	token2, _ := svc.CreateSession("admin")
	now = now.Add(2 * time.Hour)
	if svc.Valid(token2) {
		t.Fatal("expired token still valid")
	}
	if _, ok := svc.Session(token2); ok {
		t.Fatal("expired session returned")
	}
}

func TestRateLimit(t *testing.T) {
	svc := New("admin", "password", true, time.Hour)
	now := time.Unix(2000, 0)
	svc.now = func() time.Time { return now }

	for i := 0; i < maxAttempts; i++ {
		if !svc.AllowAttempt("1.2.3.4") {
			t.Fatalf("attempt %d blocked too early", i)
		}
		svc.RecordFailure("1.2.3.4")
	}
	if svc.AllowAttempt("1.2.3.4") {
		t.Fatal("attempts should be blocked")
	}
	if !svc.AllowAttempt("5.6.7.8") {
		t.Fatal("other IP should not be blocked")
	}
	now = now.Add(attemptWindow + time.Second)
	if !svc.AllowAttempt("1.2.3.4") {
		t.Fatal("window should have expired")
	}

	svc.RecordFailure("9.9.9.9")
	svc.ResetAttempts("9.9.9.9")
	for i := 0; i < maxAttempts; i++ {
		if !svc.AllowAttempt("9.9.9.9") {
			t.Fatalf("reset failed at attempt %d", i)
		}
		svc.RecordFailure("9.9.9.9")
	}
}

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if len(a) < 20 {
		t.Fatalf("password too short: %q", a)
	}
	if a == b {
		t.Fatal("generated passwords should differ")
	}
}

func TestDisabled(t *testing.T) {
	svc := New("admin", "", false, time.Hour)
	if svc.Enabled() {
		t.Fatal("service should be disabled")
	}
}
