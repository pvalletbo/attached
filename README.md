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

## Attaching to your first remote session

You must have two available hosts:

* Client: the host that you will be controlling
* Publisher: remote hosts that is serving a Herdr session to the client. This may be any kind of machine, 
as long at can run herdr (a docker container would do it as well) 

Both hosts must have Herdr installed. You can find the instructions to install it 
[here](https://herdr.dev/docs/install/). 

Conceptually, these are the steps that you will be doing: 

1. Create a new Attached account in your client machine. No PII data required.
2. Generate the `publish.bundle`, which contains the information required by the publisher.
3. Run the `attached serve` command passing the `publish.bundle` in the publisher machine. 
4. From the client host, connect to the remote session. 








