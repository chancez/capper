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

func GetPodNameNamespace(ctx context.Context, ctr containerd.Container) (namespace, name string, err error) {
	labels, err := ctr.Labels(ctx)
	if err != nil {
		return "", "", err
	}

	name = labels["io.kubernetes.pod.name"]
	namespace = labels["io.kubernetes.pod.namespace"]
	return
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
		foundPod, foundNamespace, err := GetPodNameNamespace(ctrCtx, ctr)
		if err != nil {
			return nil, err
		}
		if foundNamespace != "" && foundPod != "" {
			break
		}
		podCtr = ctr
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
