package containerd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

func New(addr string) (*containerd.Client, error) {
	return containerd.New(addr, containerd.WithDefaultNamespace("k8s.io"))
}

type Pod struct {
	Name      string
	Namespace string
	Netns     string
}

func GetPod(ctx context.Context, client *containerd.Client, podName, namespace string) (Pod, error) {
	if podName == "" || namespace == "" {
		return Pod{}, errors.New("invalid arguments, pod and namespace must be non-empty")
	}

	ctrCtx := namespaces.WithNamespace(ctx, "k8s.io")
	filters := []string{
		fmt.Sprintf("labels.io.kubernetes.namespace.name==%s", namespace),
		fmt.Sprintf("labels.io.kubernetes.pod.name==%s", podName),
	}
	filter := strings.Join(filters, ",")
	cs, err := client.Containers(ctrCtx, filter)
	if err != nil {
		return Pod{}, err
	}
	if len(cs) == 0 {
		// no containers matching
		return Pod{}, nil
	}
	// All containers in the pod share a network namespace.
	ctr := cs[0]
	spec, err := ctr.Spec(ctrCtx)
	if err != nil {
		return Pod{}, err
	}

	pod := Pod{
		Namespace: namespace,
	}
	labels, err := ctr.Labels(ctrCtx)
	if err == nil {
		pod.Name = labels["io.kubernetes.pod.name"]
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "network" {
			pod.Netns = ns.Path
		}
	}
	return pod, nil
}
