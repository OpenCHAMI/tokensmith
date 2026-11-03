//go:build !darwin && !linux

package tokenservice

import "os"

func validateStoreRootOwner(os.FileInfo) error { return nil }
