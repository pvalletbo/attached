# Attached

Attach to remote Herdr sessions no matter where they run.

Attached uses secure peer-to-peer connections, together with a passive synchronization service,
to provide a safe way to attach to remote Herdr sessions without having to deal with any networking.
A good use case is attaching to ephemeral Herdr sessions spawned by AI agents running anywhere.

Watch the video below to see how to publish a session from a Docker container and connect to it from
the outside.

![Attached terminal demo showing a consumer connected to a Herdr session running in Docker](demo/attached-demo.gif)

## Install

### Curl

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://install.attached.sh | sh
```

### Cargo

```bash
cargo install --git https://github.com/pvalletbo/attached.git --locked attached
```

You can verify that Attached is correctly installed by running `attached --version`. Although not mandatory,
it is highly recommended to have [fzf](https://junegunn.github.io/fzf/)
installed as well for a better experience when attaching to remote sessions.

## Attaching to your first remote session

You must have two available hosts:

* **Client**: the local host from which you will control the remote session
* **Publisher**: the remote host serving a Herdr session to the client. This may be any kind of machine,
  as long as it can run Herdr (a Docker container works as well)

Both hosts must have Herdr installed. You can find the installation instructions
[here](https://herdr.dev/docs/install/).

```bash
# Client host
# Create an Attached account. No PII data is required.
# You will need to create a password to protect the files written locally.
attached account create
# Export the publisher-only credentials. They will be copied to your clipboard.
attached account export --type publish

# Publisher host
# On the publisher, start publishing its Herdr sessions.
# You will need to paste the publish-only bundle previously copied to the clipboard.
attached serve --host-label your-remote-session

# Back on the client, select and attach to the remote session.
attached attach
```

You should see something like the image below. Select the desired session, and you will be attached
to the remote Herdr session.

![Attached session selection](./docs/img/attached_attach.png)

## How it works

To attach to remote Herdr sessions, a secure peer-to-peer channel must be established. Instead of
implementing a custom solution to create this channel, Attached uses [Iroh](https://www.iroh.computer/)
under the hood to create P2P QUIC connections in which all transmitted bytes are end-to-end encrypted.
This means that no one except the two ends of the tunnel can read the commands sent between the Herdr
client and server.

To establish the tunnel, the client, which initiates the communication, must have enough information
to tell the server that it intends to start a tunnel. This is equivalent to knowing an IP address in a
regular HTTP message exchange. However, Iroh uses public keys instead of IP addresses because IP
addresses may change. Both the server and client have a public-private key pair used to secure the
tunnel. The server's public key is also used to perform an address lookup and determine how the server
can be reached over the Internet. Once this information is known, a NAT traversal ceremony attempts to
establish direct communication between the peers, using the cryptographic keys to secure the channel.
More information is available in the [Iroh documentation](https://docs.iroh.computer/concepts/endpoints).

Apart from sharing the Iroh connection details, the publisher and client need to share information
about the active Herdr sessions, such as the hostname and active session names. To share this information
securely, we rely on a backend service that stores the information in an encrypted form so that it can
never read or write the data. The publisher encrypts the information and pushes it to the server. The
client can then retrieve and decrypt it and start an attachment if active sessions are available. Among
other technical details, the following information is shared:

* **Host label**: a descriptive name for the host
* **Iroh endpoint ticket**: used by the consumer to establish the P2P tunnel
* **Attach capability**: a shared secret that the consumer must present to authorize the tunnel
* **Attached version**: the running version of the Attached binary
* **Herdr version**: the running version of Herdr
* **Sessions**: a list of the Herdr session names running on the remote machine

