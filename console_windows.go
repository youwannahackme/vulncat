//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func initConsole() {
	// Use lazy-loaded kernel32.dll to dynamically enable Virtual Terminal processing.
	// This avoids compilation errors on non-Windows systems where syscall.SetConsoleMode is undefined.
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")

	handleOut, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err == nil {
		var mode uint32
		r, _, errCall := getConsoleMode.Call(uintptr(handleOut), uintptr(unsafe.Pointer(&mode)))
		if r != 0 && errCall == nil || errCall.Error() == "The operation completed successfully." {
			mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
			_, _, _ = setConsoleMode.Call(uintptr(handleOut), uintptr(mode))
		}
	}

	handleErr, err := syscall.GetStdHandle(syscall.STD_ERROR_HANDLE)
	if err == nil {
		var mode uint32
		r, _, errCall := getConsoleMode.Call(uintptr(handleErr), uintptr(unsafe.Pointer(&mode)))
		if r != 0 && errCall == nil || errCall.Error() == "The operation completed successfully." {
			mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
			_, _, _ = setConsoleMode.Call(uintptr(handleErr), uintptr(mode))
		}
	}
}
