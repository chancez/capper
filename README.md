# capper

Capper is a distributed tcpdump tool.

Use it to help you diagnose and troubleshoot network issues in your environments.

## How it works

Using [libpcap](https://www.tcpdump.org) capper can capture packets just like `tcpdump` or `Wireshark`, but it offers a set of server components for remotely capturing packets.

The `capper server` component exposes a GRPC API which can be remotely queried using `capper remote-capture`.

You can also run the `capper gateway` which acts as a relay that federates queries to multiple `capper servers`, combining the results and streaming them back to the client.

### Features

- Timed captures, run a capture for a specified amount of time then automatically stop.
- Limited captures. Specify a number of packets to capture before stopping>
- Capture packets on hosts or in containers.
- Capturing from multiple interfaces
- Supports targeting Kubernetes pods via containerd integration
  - Targeting and capturing from multiple pods
  - Support capturing by namespace without pod names
- pcapng output

Planned features (in no particular order):

- Support capturing by pod labels/namespace labels
- Better default output (similar to `tcpdump` or `tshark`)
- Helm chart

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

## Demo

[![asciicast](https://asciinema.org/a/jIKPiveVtiVnF9U10OmRJBYac.svg)](https://asciinema.org/a/jIKPiveVtiVnF9U10OmRJBYac)
