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

* Client: the host that you will be controlling
* Publisher: remote hosts that is serving a Herdr session to the client. This may be any kind of machine, 
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


