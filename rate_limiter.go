package main

import (
	"net"
	"sync"
	"time"
)

type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (rl *rateLimiter) allow(remoteAddr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	ip := clientIP(remoteAddr)

	now := time.Now()
	cutoff := now.Add(-rl.window)

	recent := []time.Time{}
	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		rl.requests[ip] = recent
		return false
	}

	recent = append(recent, now)
	rl.requests[ip] = recent
	return true
}

var authLimiter = newRateLimiter(10, time.Second)
