package orghost

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

// OrgHostServiceID is the service entry by which an org's DID names the host
// that serves its repository.
const OrgHostServiceID = "dimo_org_host"

// DocumentSource resolves DID documents. The DID directory is the one that
// counts (pkg/client.Client); tests supply their own.
type DocumentSource interface {
	Resolve(ctx context.Context, did string) (*did.DIDDocument, error)
}

// errNotThisHost is register's answer when the org's DID does not publish
// this host as its #dimo_org_host.
const errNotThisHost = "the org's DID does not name this host as #dimo_org_host"

// namesThisHost reports whether org's DID document publishes a
// #dimo_org_host service whose endpoint is exactly publicURL. A DID the
// directory does not hold, or holds deactivated, names no host. An error means
// the directory could not be asked.
func namesThisHost(ctx context.Context, docs DocumentSource, org, publicURL string) (bool, error) {
	doc, err := docs.Resolve(ctx, org)
	if errors.Is(err, client.ErrNotFound) || errors.Is(err, client.ErrGone) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, s := range doc.Service {
		if s.ID == "#"+OrgHostServiceID || s.ID == org+"#"+OrgHostServiceID {
			return publicURL != "" && s.ServiceEndpoint == publicURL, nil
		}
	}
	return false, nil
}

// rateLimiter admits at most limit events in any rolling minute. A limit of
// zero or less admits everything.
type rateLimiter struct {
	limit int

	mu   sync.Mutex
	hits []time.Time // admitted events of the last minute, oldest first
}

// allow admits an event at now, or says how long until one would be.
func (l *rateLimiter) allow(now time.Time) (bool, time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	i := 0
	for i < len(l.hits) && !l.hits[i].After(cutoff) {
		i++
	}
	l.hits = l.hits[i:]
	if len(l.hits) >= l.limit {
		return false, l.hits[0].Sub(cutoff)
	}
	l.hits = append(l.hits, now)
	return true, 0
}

// callerLimiter is a rateLimiter per caller DID. Callers whose window has
// emptied are dropped as it goes, so the map holds only callers seen in the
// last minute.
type callerLimiter struct {
	limit int

	mu      sync.Mutex
	callers map[string]*rateLimiter
	swept   time.Time
}

// allow admits one event by caller at now, or says how long until one would be.
func (l *callerLimiter) allow(caller string, now time.Time) (bool, time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.callers == nil {
		l.callers = map[string]*rateLimiter{}
	}
	if now.Sub(l.swept) >= time.Minute {
		cutoff := now.Add(-time.Minute)
		for did, r := range l.callers {
			if n := len(r.hits); n == 0 || !r.hits[n-1].After(cutoff) {
				delete(l.callers, did)
			}
		}
		l.swept = now
	}
	r, ok := l.callers[caller]
	if !ok {
		r = &rateLimiter{limit: l.limit}
		l.callers[caller] = r
	}
	return r.allow(now)
}

// retryAfterSeconds rounds a wait up to whole seconds, at least one.
func retryAfterSeconds(wait time.Duration) int {
	return max(1, int(math.Ceil(wait.Seconds())))
}
