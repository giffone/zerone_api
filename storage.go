package zero

import (
	"fmt"
	"sync"
	"time"
)

type storage struct {
	mu           sync.RWMutex
	pendingToken *token
}

func (s *storage) getToken(domain, accessToken string) error {
	s.mu.RLock()
	created := s.pendingToken != nil
	expired := false
	if created {
		expired = isExpired(s.pendingToken.payload.Exp)
	}
	s.mu.RUnlock()

	// if not created
	if !created {
		req := requestToken{
			domain:  domain,
			urlPath: fmt.Sprintf("/api/auth/token?token=%s", accessToken),
			headers: nil,
			data:    nil,
		}
		token, err := req.do()
		if err != nil {
			return fmt.Errorf("request token: %s", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.pendingToken = token
		return nil
	}

	// if expired and need to refresh
	if expired {
		req := requestToken{
			domain:  domain,
			urlPath: "/api/auth/refresh",
			headers: map[string]string{"x-jwt-token": s.pendingToken.base64},
			data:    nil,
		}
		token, err := req.do()
		if err != nil {
			return fmt.Errorf("refresh token: %s", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.pendingToken = token
		return nil
	}

	// if exists and actual
	return nil
}

func isExpired(date int64) bool {
	diff := date - time.Now().Add(-24*time.Hour).Unix()/1000
	return diff <= 0
}
