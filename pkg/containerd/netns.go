package containerd

import (
	"context"
	"errors"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

var ErrPodNotFound = errors.New("pod not found")

func New(addr string) (*containerd.Client, error) {
	return containerd.New(addr, containerd.WithDefaultNamespace("k8s.io"))
}

type Pod struct {
	Name      string
	Namespace string
	Netns     string
}

func GetPod(ctx context.Context, client *containerd.Client, podName, namespace string) (*Pod, error) {
	if podName == "" || namespace == "" {
		return nil, errors.New("invalid arguments, pod and namespace must be non-empty")
	}

	ctrCtx := namespaces.WithNamespace(ctx, "k8s.io")
	// We cannot filter on labels because of https://github.com/containerd/containerd/issues/5642
	cs, err := client.Containers(ctrCtx)
	if err != nil {
		return nil, err
	}
	var podCtr containerd.Container
	for _, ctr := range cs {
		labels, err := ctr.Labels(ctrCtx)
		if err != nil {
			return nil, err
		}

		foundPod, ok1 := labels["io.kubernetes.pod.name"]
		foundNamespace, ok2 := labels["io.kubernetes.pod.namespace"]
		if ok1 && ok2 && foundPod == podName && foundNamespace == namespace {
			podCtr = ctr
			break
		}
	}
	if podCtr == nil {
		// no containers matching
		return nil, ErrPodNotFound
	}
	spec, err := podCtr.Spec(ctrCtx)
	if err != nil {
		return nil, err
	}

	pod := Pod{
		Namespace: namespace,
		Name:      podName,
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "network" {
			pod.Netns = ns.Path
		}
	}
	return &pod, nil
}
