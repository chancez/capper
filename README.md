# capper

Capper is a distributed tcpdump tool.

Use it to help you diagnose and troubleshoot network issues in your environments.

## How it works

Using [libpcap](https://www.tcpdump.org) capper can capture packets just like `tcpdump` or `Wireshark`, but it offers a set of server components for remotely capturing packets.

The `capper server` component exposes a GRPC API which can be remotely queried using `capper remote-capture`.

You can also run the `capper gateway` which acts as a relay that federates queries to multiple `capper servers`, aggregates the results and streams them back to the client.

### Features

- Timed captures, run a capture for a specified amount of time then automatically stop
- Limited captures. Specify a number of packets to capture before stopping
- Capture packets on hosts or in containers
- Supports targeting Kubernetes pods via containerd integration

Planned features (in no particular order):

- Support capturing from multiple interfaces
- Support targeting and capturing from multiple pods
- Support capturing by namespace without pod names
- Support capturing by pod labels/namespace labels
- Support capturing by k8s node name/server hostname
- Better default output (similar to `tcpdump` or `tshark`)
- Helm chart
- Automated image builds

## Building

Building on Ubuntu:

Install Go and then run the following:

```
sudo apt install libpcap-dev build-essential
make
```

## Deploy

```
kubectl apply -f k8s
```

Then to use it:

## Usage

Open a connection to the gateway:

```
kubectl port-forward svc/capper-gateway 48999:48999
```

Then run:
```
./capper remote-capture
```

Or using docker:
```
docker run --privileged --net=host -v --rm -it ghcr.io/chancez/capper:latest remote-capture --server host.docker.internal:48999
```

Run `capper --help` for all possible commands, arguments, and flags.
`capper remote-capture` and `capper local-capture` supports the basic options you would expect from tcpdump.
