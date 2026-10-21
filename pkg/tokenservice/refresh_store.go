package tokenservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

var (
	ErrRefreshTokenReplay       = errors.New("refresh token replay")
	ErrRefreshTokenRevoked      = errors.New("refresh token revoked")
	ErrRefreshFamilyExpired     = errors.New("refresh token family expired")
	ErrRefreshTokenUnknown      = errors.New("refresh token unknown")
	ErrRefreshTokenFamilyExists = errors.New("refresh token family already exists")
)

type RefreshTokenStore struct {
	storePath string
	mu        sync.RWMutex
	families  map[string]*RefreshTokenFamily
}
type refreshFamilyDisk struct {
	FamilyID                 string     `json:"family_id"`
	CurrentTokenHash         string     `json:"current_token_hash"`
	ConsumedGenerationHashes []string   `json:"consumed_generation_hashes,omitempty"`
	Subject                  string     `json:"subject"`
	Audience                 string     `json:"audience"`
	Scopes                   []string   `json:"scopes"`
	IssuedAt                 time.Time  `json:"issued_at"`
	ExpiresAt                time.Time  `json:"expires_at"`
	LastUsedAt               time.Time  `json:"last_used_at"`
	UsageCount               int        `json:"usage_count"`
	ReplayDetectedAt         *time.Time `json:"replay_detected_at,omitempty"`
	RevokedAt                *time.Time `json:"revoked_at,omitempty"`
	BindingIdentifier        string     `json:"binding_identifier,omitempty"`
}

func NewRefreshTokenStore(storePath string) (*RefreshTokenStore, error) {
	if err := os.MkdirAll(storePath, 0o755); err != nil {
		return nil, fmt.Errorf("create refresh token store directory: %w", err)
	}
	store := &RefreshTokenStore{storePath: storePath, families: make(map[string]*RefreshTokenFamily)}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}
func (s *RefreshTokenStore) GetFamily(id string) (*RefreshTokenFamily, error) {
	s.mu.RLock()
	family := s.families[id]
	s.mu.RUnlock()
	if family == nil {
		return nil, fmt.Errorf("refresh token family not found")
	}
	return cloneRefreshFamily(family), nil
}
func (s *RefreshTokenStore) GetFamilyByTokenHash(hash string) (*RefreshTokenFamily, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, family := range s.families {
		if family.CurrentTokenHash == hash || containsHash(family.ConsumedGenerationHashes, hash) {
			return cloneRefreshFamily(family), nil
		}
	}
	return nil, fmt.Errorf("refresh token family not found for token hash")
}
func (s *RefreshTokenStore) RotateOrRevoke(presentedHash, successorHash string, now time.Time) (result *RefreshTokenFamily, retErr error) {
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
	s.families = make(map[string]*RefreshTokenFamily)
	if err := s.load(); err != nil {
		return nil, err
	}
	var family *RefreshTokenFamily
	for _, candidate := range s.families {
		if candidate.CurrentTokenHash == presentedHash || containsHash(candidate.ConsumedGenerationHashes, presentedHash) {
			family = candidate
			break
		}
	}
	if family == nil {
		return nil, ErrRefreshTokenUnknown
	}
	if family.RevokedAt != nil {
		return nil, ErrRefreshTokenRevoked
	}
	if !now.Before(family.ExpiresAt) {
		return nil, ErrRefreshFamilyExpired
	}
	candidate := cloneRefreshFamily(family)
	if containsHash(candidate.ConsumedGenerationHashes, presentedHash) {
		candidate.ReplayDetectedAt = &now
		candidate.RevokedAt = &now
		committed, err := s.persist(candidate)
		if committed {
			s.families[candidate.FamilyID] = candidate
		}
		return nil, errors.Join(ErrRefreshTokenReplay, err)
	}
	if successorHash == "" || successorHash == candidate.CurrentTokenHash || containsHash(candidate.ConsumedGenerationHashes, successorHash) || s.hashOwner(successorHash, candidate.FamilyID) != "" {
		return nil, fmt.Errorf("refresh token successor hash already belongs to another family")
	}
	candidate.ConsumedGenerationHashes = append(candidate.ConsumedGenerationHashes, candidate.CurrentTokenHash)
	candidate.CurrentTokenHash = successorHash
	candidate.LastUsedAt = now
	candidate.UsageCount++
	committed, err := s.persist(candidate)
	if committed {
		s.families[candidate.FamilyID] = candidate
	}
	return cloneRefreshFamily(candidate), err
}
func (s *RefreshTokenStore) persist(family *RefreshTokenFamily) (bool, error) {
	return atomicJSONWrite(filepath.Join(s.storePath, family.FamilyID+".json"), familyToDisk(family))
}
func (s *RefreshTokenStore) load() error {
	entries, err := os.ReadDir(s.storePath)
	if err != nil {
		return fmt.Errorf("read refresh token store directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(s.storePath, entry.Name()))
		if readErr != nil {
			return fmt.Errorf("read refresh token family %q: %w", entry.Name(), readErr)
		}
		family, decodeErr := decodeRefreshFamily(data)
		if decodeErr != nil {
			return fmt.Errorf("decode refresh token family %q: %w", entry.Name(), decodeErr)
		}
		if validateRefreshFamily(family) != nil || s.families[family.FamilyID] != nil || s.hashOwner(family.CurrentTokenHash, "") != "" {
			return fmt.Errorf("invalid duplicate refresh token family %q", entry.Name())
		}
		for _, hash := range family.ConsumedGenerationHashes {
			if hash == "" || s.hashOwner(hash, "") != "" {
				return fmt.Errorf("invalid refresh token hash ownership %q", entry.Name())
			}
		}
		s.families[family.FamilyID] = family
	}
	return nil
}
func (s *RefreshTokenStore) hashOwner(hash, excludedID string) string {
	for id, family := range s.families {
		if id != excludedID && (family.CurrentTokenHash == hash || containsHash(family.ConsumedGenerationHashes, hash)) {
			return id
		}
	}
	return ""
}
func (s *RefreshTokenStore) consumedHashOwner(candidate *RefreshTokenFamily, excludedID string) string {
	for _, hash := range candidate.ConsumedGenerationHashes {
		if s.hashOwner(hash, excludedID) != "" {
			return hash
		}
	}
	return ""
}
func familyToDisk(family *RefreshTokenFamily) refreshFamilyDisk {
	return refreshFamilyDisk{family.FamilyID, family.CurrentTokenHash, append([]string(nil), family.ConsumedGenerationHashes...), family.Subject, family.Audience, append([]string(nil), family.Scopes...), family.IssuedAt, family.ExpiresAt, family.LastUsedAt, family.UsageCount, cloneTime(family.ReplayDetectedAt), cloneTime(family.RevokedAt), family.BindingIdentifier}
}
func decodeRefreshFamily(data []byte) (*RefreshTokenFamily, error) {
	var disk refreshFamilyDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, err
	}
	var legacy RefreshTokenFamily
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, err
	}
	if disk.FamilyID == "" {
		return cloneRefreshFamily(&legacy), nil
	}
	return cloneRefreshFamily(&RefreshTokenFamily{disk.FamilyID, disk.CurrentTokenHash, disk.ConsumedGenerationHashes, disk.Subject, disk.Audience, disk.Scopes, disk.IssuedAt, disk.ExpiresAt, disk.LastUsedAt, disk.UsageCount, disk.ReplayDetectedAt, disk.RevokedAt, disk.BindingIdentifier}), nil
}
func cloneRefreshFamily(family *RefreshTokenFamily) *RefreshTokenFamily {
	if family == nil {
		return nil
	}
	clone := *family
	clone.Scopes = append([]string(nil), family.Scopes...)
	clone.ConsumedGenerationHashes = append([]string(nil), family.ConsumedGenerationHashes...)
	clone.ReplayDetectedAt = cloneTime(family.ReplayDetectedAt)
	clone.RevokedAt = cloneTime(family.RevokedAt)
	return &clone
}
func containsHash(hashes []string, hash string) bool {
	return slices.Contains(hashes, hash)
}
