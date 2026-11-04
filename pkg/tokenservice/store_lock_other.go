//go:build !darwin && !linux

package tokenservice

import (
	"errors"
	"os"
)

var ErrStoreLockUnsupported = errors.New("store lock unsupported on this platform")

var beforeStoreFlock = func() {}

func lockStore(*storeRoot) (*os.File, error) { return nil, ErrStoreLockUnsupported }
func unlockStore(*os.File) error             { return nil }
