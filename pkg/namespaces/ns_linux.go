package namespaces

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func RunInNetns(f func(nsInode uint64) error, ns string) error {
	errCh := make(chan error)
	defer close(errCh)
	go func() {
		// We lock this thread because we need to setns(2) here. There is no
		// UnlockOSThread() here, to ensure that the Go runtime will kill this
		// thread once this goroutine returns (ensuring no other goroutines run
		// in this context).
		runtime.LockOSThread()

		nsFd, err := os.Open(ns)
		if err != nil {
			errCh <- fmt.Errorf("error opening netns: %w", err)
			return
		}
		fd := int(nsFd.Fd())
		var stat unix.Stat_t
		err = unix.Fstat(fd, &stat)
		if err != nil {
			errCh <- fmt.Errorf("error opening netns: %w", err)
			return
		}
		defer nsFd.Close()
		if err := unix.Setns(fd, syscall.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("error setting netns: %w", err)
			return
		}
		if err := f(stat.Ino); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	return <-errCh
}
