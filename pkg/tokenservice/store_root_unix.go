//go:build darwin || linux

package tokenservice

import (
	"fmt"
	"os"
	"syscall"
)

func validateStoreRootOwner(info os.FileInfo) error {
	return validateStoreRootOwnerForEUID(info, os.Geteuid())
}

func validateStoreRootOwnerForEUID(info os.FileInfo, euid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect store root owner")
	}
	if int(stat.Uid) != euid {
		return fmt.Errorf("store root must be owned by the current user")
	}
	return nil
}
