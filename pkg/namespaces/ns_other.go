//go:build !linux
// +build !linux

package namespaces

func RunInNetns(func() error, string) error {
	panic("unsupported")
}
