# MPQUIC-video-streaming
Video streaming using Multipath QUIC protocol

## Requirements

1. Install GO
2. Install MPQUIC from [here](https://github.com/qdeconinck/mp-quic). Follow installation step given [here](https://multipath-quic.org/2017/12/09/artifacts-available.html)


## Usage

1. from `/server` run: `go run server.go`
2. from `/client` run: `go run client.go`

## Detecting multipaths using Wireshark
1. Listen on interface *any
2. use filter `udp.port == 8000`

*Note: make sure you are connected to atleast one interface*