package containerd

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

func New(addr string) (*containerd.Client, error) {
	return containerd.New(addr, containerd.WithDefaultNamespace("k8s.io"))
}

func GetPodNetns(ctx context.Context, client *containerd.Client, pod, namespace string) (string, error) {
	if pod == "" || namespace == "" {
		return "", errors.New("invalid arguments, pod and namespace must be non-empty")
	}

	ctrCtx := namespaces.WithNamespace(ctx, "k8s.io")
	filter := fmt.Sprintf("labels.io.kubernetes.pod.name==%s,labels.io.kubernetes.pod.namespace==%s", pod, namespace)
	cs, err := client.Containers(ctrCtx, filter)
	if err != nil {
		return "", err
	}
	if len(cs) == 0 {
		// no containers matching
		return "", nil
	}
	// All containers in the pod share a network namespace.
	ctr := cs[0]
	spec, err := ctr.Spec(ctrCtx)
	if err != nil {
		return "", err
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "network" {
			return ns.Path, nil
		}
	}
	// If we get here, the pod was found but did not have a network namespace set
	return "", nil
}
