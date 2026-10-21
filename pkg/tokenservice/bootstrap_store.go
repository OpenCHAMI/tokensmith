package tokenservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrBootstrapTokenConsumed = errors.New("bootstrap token consumed")
	ErrBootstrapTokenExpired  = errors.New("bootstrap token expired")
)

type BootstrapTokenStore struct {
	storePath string
	mu        sync.RWMutex
	policies  map[string]*BootstrapTokenPolicy
}

func NewBootstrapTokenStore(storePath string) (*BootstrapTokenStore, error) {
	if err := os.MkdirAll(storePath, 0o755); err != nil {
		return nil, fmt.Errorf("create bootstrap token store directory: %w", err)
	}
	store := &BootstrapTokenStore{storePath: storePath, policies: make(map[string]*BootstrapTokenPolicy)}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *BootstrapTokenStore) SavePolicy(policy *BootstrapTokenPolicy) (retErr error) {
	candidate := cloneBootstrapPolicy(policy)
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := lockStore(s.storePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := unlockStore(lock); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	s.policies = make(map[string]*BootstrapTokenPolicy)
	if err := s.load(); err != nil {
		return err
	}
	if err := validateBootstrapPolicy(candidate, s.policies); err != nil {
		return err
	}
	committed, err := s.persist(candidate)
	if committed {
		s.policies[candidate.TokenHash] = candidate
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *BootstrapTokenStore) UpdatePolicy(policy *BootstrapTokenPolicy) error {
	return s.SavePolicy(policy)
}

func (s *BootstrapTokenStore) GetPolicy(tokenHash string) (*BootstrapTokenPolicy, error) {
	s.mu.RLock()
	policy := s.policies[tokenHash]
	s.mu.RUnlock()
	if policy != nil {
		return cloneBootstrapPolicy(policy), nil
	}
	policy, err := s.loadOne(tokenHash)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.policies[tokenHash]; existing != nil {
		return cloneBootstrapPolicy(existing), nil
	}
	s.policies[tokenHash] = policy
	return cloneBootstrapPolicy(policy), nil
}

func (s *BootstrapTokenStore) GetLatestPolicyBySubject(subject string) (*BootstrapTokenPolicy, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("subject is required")
	}
	s.mu.RLock()
	var latest *BootstrapTokenPolicy
	for _, policy := range s.policies {
		if policy.Subject == subject && (latest == nil || policy.CreatedAt.After(latest.CreatedAt)) {
			latest = policy
		}
	}
	s.mu.RUnlock()
	if latest == nil {
		return s.loadLatestFromDisk(subject)
	}
	return cloneBootstrapPolicy(latest), nil
}

func (s *BootstrapTokenStore) ConsumePolicy(tokenHash, clientIP string, now time.Time) (result *BootstrapTokenPolicy, retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := lockStore(s.storePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := unlockStore(lock); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	s.policies = make(map[string]*BootstrapTokenPolicy)
	if err := s.load(); err != nil {
		return nil, err
	}
	policy := s.policies[tokenHash]
	if policy == nil {
		return nil, fmt.Errorf("bootstrap token policy not found")
	}
	if !now.Before(policy.ExpiresAt) {
		return cloneBootstrapPolicy(policy), ErrBootstrapTokenExpired
	}
	if policy.ConsumedAt != nil {
		return cloneBootstrapPolicy(policy), ErrBootstrapTokenConsumed
	}
	candidate := cloneBootstrapPolicy(policy)
	candidate.ConsumedAt = &now
	candidate.ConsumedByIP = clientIP
	committed, err := s.persist(candidate)
	if committed {
		s.policies[tokenHash] = candidate
	}
	return cloneBootstrapPolicy(candidate), err
}

func (s *BootstrapTokenStore) persist(policy *BootstrapTokenPolicy) (bool, error) {
	return atomicJSONWrite(filepath.Join(s.storePath, policy.TokenHash+".json"), policyToDisk(policy))
}

func (s *BootstrapTokenStore) load() error {
	entries, err := os.ReadDir(s.storePath)
	if err != nil {
		return fmt.Errorf("read bootstrap token store directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(s.storePath, entry.Name()))
		if readErr != nil {
			return fmt.Errorf("read bootstrap policy %q: %w", entry.Name(), readErr)
		}
		policy, decodeErr := decodeBootstrapPolicy(data)
		if decodeErr != nil {
			return fmt.Errorf("decode bootstrap policy %q: %w", entry.Name(), decodeErr)
		}
		if err := validateBootstrapPolicy(policy, s.policies); err != nil {
			return fmt.Errorf("invalid duplicate bootstrap policy %q", entry.Name())
		}
		s.policies[policy.TokenHash] = policy
	}
	return nil
}

func (s *BootstrapTokenStore) loadOne(hash string) (*BootstrapTokenPolicy, error) {
	data, err := os.ReadFile(filepath.Join(s.storePath, hash+".json"))
	if err != nil {
		return nil, fmt.Errorf("bootstrap token policy not found: %w", err)
	}
	policy, err := decodeBootstrapPolicy(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal bootstrap policy file: %w", err)
	}
	if policy.TokenHash != hash {
		return nil, fmt.Errorf("bootstrap token hash mismatch")
	}
	return policy, nil
}

func (s *BootstrapTokenStore) loadLatestFromDisk(subject string) (*BootstrapTokenPolicy, error) {
	entries, err := os.ReadDir(s.storePath)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap token store directory: %w", err)
	}
	var latest *BootstrapTokenPolicy
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.storePath, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read bootstrap policy %q: %w", entry.Name(), err)
		}
		policy, err := decodeBootstrapPolicy(data)
		if err != nil {
			return nil, fmt.Errorf("decode bootstrap policy %q: %w", entry.Name(), err)
		}
		if policy.Subject == subject && (latest == nil || policy.CreatedAt.After(latest.CreatedAt)) {
			latest = policy
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("bootstrap token policy not found for subject %q", subject)
	}
	s.mu.Lock()
	s.policies[latest.TokenHash] = latest
	s.mu.Unlock()
	return cloneBootstrapPolicy(latest), nil
}

func cloneBootstrapPolicy(policy *BootstrapTokenPolicy) *BootstrapTokenPolicy {
	if policy == nil {
		return nil
	}
	clone := *policy
	clone.Scopes = append([]string(nil), policy.Scopes...)
	clone.ReplayAttempts = append([]time.Time(nil), policy.ReplayAttempts...)
	clone.ConsumedAt = cloneTime(policy.ConsumedAt)
	return &clone
}
func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
