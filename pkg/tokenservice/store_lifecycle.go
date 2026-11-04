package tokenservice

// Close releases the pinned directory descriptor.
func (s *BootstrapTokenStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	return s.root.Close()
}

// Close releases the pinned directory descriptor.
func (s *RefreshTokenStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	return s.root.Close()
}
