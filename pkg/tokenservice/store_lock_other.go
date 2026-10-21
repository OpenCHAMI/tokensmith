//go:build !darwin && !linux

package tokenservice

import (
	"errors"
	"os"
)

var ErrStoreLockUnsupported = errors.New("store lock unsupported on this platform")

func lockStore(string) (*os.File, error) { return nil, ErrStoreLockUnsupported }
func unlockStore(*os.File) error         { return nil }
