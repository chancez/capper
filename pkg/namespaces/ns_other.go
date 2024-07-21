//go:build !linux
// +build !linux

package namespaces

func RunInNetns(func(uint64) error, string) error {
	panic("unsupported")
}
