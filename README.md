# Attached

Attach to remote Herdr sessions no matter where they run. 

Attached uses secure peer to peer connections, together with a passive synchronization service, 
to provide a safe way to attach to remote Herdr sessions without having to deal with any networking. 
A good use case for it is to attach to ephimeral Herdr sessions spawned by AI agents running anywhere. 

Check the video below to see how to publish a session from a docker container and connect to it from 
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

You can verify that herdr is correctly installed by running `herdr --version`. Although not mandatory, 
it is highly recommended to have [fzf](https://junegunn.github.io/fzf/)
installed as well for a better UX when attaching to remote sessions. 

## Attaching to your first remote session

You must have two available hosts:

* **Client**: the host that you will be controlling
* **Publisher**: remote hosts that is serving a Herdr session to the client. This may be any kind of machine, 
as long at can run herdr (a docker container would do it as well) 

Both hosts must have Herdr installed. You can find the instructions to install it 
[here](https://herdr.dev/docs/install/). 

```bash
# Client host
# create an Attached account. No PII data is required.
# You will need to add a password to protect the files written locally. 
attached account create
# Export the publisher-only credentials. They will be copied in your clipboard
attached account export --type publish 

# Publisher host
# On the publisher, start publishing its Herdr sessions.
# You will need to paste the publish.bundle that was previously copied to the clipboard. 
attached serve --host-label your-remote-session

# Back on the client, select and attach to the remote session.
attached attach
```

You should see something like the image below. You can just select the desired session and 
you'll be attached to the remote herdr session. 

![attahed attach](./docs/img/attached_attach.png)

## How it works

To attach to remote herdr sessions a secure peer2peer channel must be established. Instead of 
implementing a custom solution to create this channel, attached uses [iroh](https://www.iroh.computer/)
under the hood to create P2P QUIC connections where all the transmitted 
bytes are end to end encrypted. This means that no one except the two ens of the 
tunnel can read the commands sent between the herdr client and server. 

To establish the tunnel the client, who will start the communication, must know some information 
to let the server know the intention of starting the tunnel. This would be the equivalent of an IP 
address in a regular HTTP messages exchange. However, in Iroh we do not use IP addresses, as the may change,  
instead we use public keys. Both the server and client have a pair of public and private keys that 
will be used to secure the tunnel. However, the public key of the server is also used to make an 
address lookup in order to understand the networking details of how the server can be reached from the 
Internet. Once this information is known, there is a NAT traversal cermony to try to make the 
communication direct between the peers, using the cryptographic keys as a way to secure the channel. 
More information about this can be found in the [iroh docs](https://docs.iroh.computer/concepts/endpoints).

Apart from sharing the iroh connection details, the publisher and client need to share information 
about the active herdr sessions, such as the hostname and the active sessions name. To share this information
securely we rely on a backend service that will store the information encrypted, in a way that 
it can never read nor write data. The publisher will encrypt the information, push it to the server, 
and then the client will be able to retrieve it, decrypt it, and start an attachment if active sessions
are available. Among other technical details, this is the information that is being shared: 

* **Host label**: descriptive name of the host
* **Iroh endpoint ticket**: used by the consumer to establish the p2p tunnel
* **Attach capability**: a shared secret that the consumer will need to present in order to authorize the tunnel
* **Attached version**: running version of the attached binary
* **Herdr version**: running version of herdr
* **Sessions**: a list of the herdr session names running in the remote machine




