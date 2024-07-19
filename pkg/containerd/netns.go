package containerd

import (
	"context"
	"errors"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"

	capperpb "github.com/chancez/capper/proto/capper"
)

var ErrPodNotFound = errors.New("pod not found")

func New(addr string) (*containerd.Client, error) {
	return containerd.New(addr, containerd.WithDefaultNamespace("k8s.io"))
}

type Pod struct {
	*capperpb.Pod
	Netns string
}

func GetContainerPod(ctx context.Context, ctr containerd.Container) (*capperpb.Pod, error) {
	labels, err := ctr.Labels(ctx)
	if err != nil {
		return nil, err
	}

	name, ok1 := labels["io.kubernetes.pod.name"]
	namespace, ok2 := labels["io.kubernetes.pod.namespace"]
	if ok1 && ok2 {
		return &capperpb.Pod{
			Namespace: namespace,
			Name:      name,
		}, nil
	}
	return nil, nil
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
	for _, ctr := range cs {
		foundPod, err := GetContainerPod(ctrCtx, ctr)
		if err != nil {
			return nil, err
		}
		if foundPod == nil {
			continue
		}
		spec, err := ctr.Spec(ctrCtx)
		if err != nil {
			return nil, err
		}
		var netns string
		for _, ns := range spec.Linux.Namespaces {
			if ns.Type == "network" {
				netns = ns.Path
			}
		}
		return &Pod{
			Pod:   foundPod,
			Netns: netns,
		}, nil
	}
	// no containers matching
	return nil, ErrPodNotFound
}
