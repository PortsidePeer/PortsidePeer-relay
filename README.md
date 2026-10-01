# PortsidePeer relay

1. Download latest release. (soon)

2. Set allow list mode after creating allow list.

`vim allowed_peers.txt` and add the public node ids.

`export RELAY_ENFORCE_ALLOWLIST=1`

3. Then run the relay.

`./portsidepeer-relay`

Add relay public peer node id to your clients. Most of the time the clients will autodetect the node after setting up the relay endpoint.
