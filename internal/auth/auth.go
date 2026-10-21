// Package auth provides password authentication with in-memory sessions and
// simple login rate limiting for the ebpfshark HTTP API.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// CookieName is the session cookie used by the HTTP layer.
const CookieName = "ebpfshark_session"

// DefaultTTL is how long a login session stays valid.
const DefaultTTL = 12 * time.Hour

const (
	maxAttempts    = 10
	attemptWindow  = 5 * time.Minute
	passwordLength = 18 // bytes of entropy before base64 encoding
)

// Session is a logged-in user session.
type Session struct {
	User    string
	Expires time.Time
}

type attempt struct {
	count int
	reset time.Time
}

// Service validates credentials and manages sessions.
type Service struct {
	mu       sync.Mutex
	enabled  bool
	userHash [32]byte
	passHash [32]byte
	ttl      time.Duration
	sessions map[string]Session
	attempts map[string]*attempt
	now      func() time.Time
}

// New creates an auth service. When enabled is false every request is allowed.
func New(user, password string, enabled bool, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Service{
		enabled:  enabled,
		userHash: sha256.Sum256([]byte(user)),
		passHash: sha256.Sum256([]byte(password)),
		ttl:      ttl,
		sessions: make(map[string]Session),
		attempts: make(map[string]*attempt),
		now:      time.Now,
	}
}

// Enabled reports whether authentication is active.
func (s *Service) Enabled() bool {
	return s != nil && s.enabled
}

// Authenticate checks a username/password pair in constant time.
func (s *Service) Authenticate(user, password string) bool {
	u := sha256.Sum256([]byte(user))
	p := sha256.Sum256([]byte(password))
	userOK := subtle.ConstantTimeCompare(u[:], s.userHash[:]) == 1
	passOK := subtle.ConstantTimeCompare(p[:], s.passHash[:]) == 1
	return userOK && passOK
}

// CreateSession issues a new session token.
func (s *Service) CreateSession(user string) (string, time.Time) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("auth: cannot read random bytes: " + err.Error())
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	expires := s.now().Add(s.ttl)

	s.mu.Lock()
	s.cleanupLocked()
	s.sessions[token] = Session{User: user, Expires: expires}
	s.mu.Unlock()
	return token, expires
}

// Session returns the session for token if it exists and has not expired.
func (s *Service) Session(token string) (Session, bool) {
	if s == nil || token == "" {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return Session{}, false
	}
	if !s.now().Before(sess.Expires) {
		delete(s.sessions, token)
		return Session{}, false
	}
	return sess, true
}

// Valid reports whether token refers to a live session.
func (s *Service) Valid(token string) bool {
	_, ok := s.Session(token)
	return ok
}

// DeleteSession invalidates a token.
func (s *Service) DeleteSession(token string) {
	if s == nil || token == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// AllowAttempt reports whether ip may currently attempt to log in.
func (s *Service) AllowAttempt(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[ip]
	if !ok || !s.now().Before(a.reset) {
		return true
	}
	return a.count < maxAttempts
}

// RecordFailure records a failed login attempt for ip.
func (s *Service) RecordFailure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	now := s.now()
	a, ok := s.attempts[ip]
	if !ok || !now.Before(a.reset) {
		s.attempts[ip] = &attempt{count: 1, reset: now.Add(attemptWindow)}
		return
	}
	a.count++
}

// ResetAttempts clears the failure counter for ip after a successful login.
func (s *Service) ResetAttempts(ip string) {
	s.mu.Lock()
	delete(s.attempts, ip)
	s.mu.Unlock()
}

func (s *Service) cleanupLocked() {
	now := s.now()
	for token, sess := range s.sessions {
		if !now.Before(sess.Expires) {
			delete(s.sessions, token)
		}
	}
	for ip, a := range s.attempts {
		if !now.Before(a.reset) {
			delete(s.attempts, ip)
		}
	}
}

// GeneratePassword returns a URL-safe random password for first-run setups.
func GeneratePassword() (string, error) {
	raw := make([]byte, passwordLength)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
