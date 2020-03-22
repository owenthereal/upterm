# Upterm

[Upterm](https://github.com/jingweno/upterm) is an open-source solution for sharing terminal sessions instantly with the public internet over secure tunnels.

## What it's good for

* Remote pair programming
* Access remote computers behind NATs and firewalls
* Remote debugging
* \<insert your creative use cases\>

## How it works

You run the `upterm` program and specify the command for your terminal session.
Upterm starts an SSH server (a.k.a. `sshd`) in the host machine and sets up a reverse SSH tunnel to a [Upterm server](https://github.com/jingweno/upterm/tree/master/cmd/uptermd) (a.k.a. `uptermd`).
Clients connect to your terminal session over the public internet via `uptermd` using `ssh` via TCP or WebSocket.
A community Upterm server is running at `uptermd.upterm.dev` and `upterm` points to this server by default.

![upterm flowchart](https://raw.githubusercontent.com/jingweno/upterm/gh-pages/upterm-flowchart.svg?sanitize=true)

## Demo

[![asciicast](https://asciinema.org/a/AnXTj0pOOtvSWALjUIQ63OKDm.svg)](https://asciinema.org/a/AnXTj0pOOtvSWALjUIQ63OKDm)

## Installation

### Mac

```
brew install jingweno/upterm/upterm
```

### Standalone

`upterm` can be easily installed as an executable. Download the latest [compiled binaries](https://github.com/jingweno/upterm/releases) and put it in your executable path.

### From source

```
git clone git@github.com:jingweno/upterm.git
cd upterm
go install ./cmd/upterm/...
```

## Quick Start

```bash
# Host a terminal session that runs $SHELL with
# client's input/output attaching to the host's
$ upterm host

# Display the ssh connection string and share it with
# the client(s)
$ upterm session current
=== SESSION_ID
Command:                /bin/bash
Force Command:          n/a
Host:                   ssh://uptermd.upterm.dev:22
SSH Session:            ssh TOKEN@uptermd.upterm.dev

# A client connects to the host session with ssh
$ ssh TOKEN@uptermd.upterm.dev

# Host a session with a custom command
$ upterm host -- docker run --rm -ti ubuntu bash

# Host a session that runs 'tmux new -t pair-programming' and
# force clients to join with 'tmux attach -t pair-programming'.
# This is similar to tmate.
$ upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming`,

# Use a different Uptermd server and host a session via WebSocket
$ upterm host --server wss://YOUR_UPTERMD_SERVER -- YOUR_COMMAND

# A client connects to the host session via WebSocket
$ ssh -o ProxyCommand='upterm proxy wss://TOKEN@YOUR_UPTERMD_SERVER' TOKEN@YOUR_UPTERMD_SERVER:443
```

More advanced usage is [here](https://github.com/jingweno/upterm/blob/master/docs/upterm.md).

## Deploy Uptermd

The easiest and the cheapest way to deploy a [Upterm server](https://github.com/jingweno/upterm/tree/master/cmd/uptermd) (a.k.a. `uptermd`) is to use [Heroku](https://heroku.com).
Heroku offers [free Dyno hours](https://www.heroku.com/pricing) which should be sufficient for most cacusal uses.

You can deploy with one click of the following button:

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

You can also automate the deployment with [Heroku Terraform](https://devcenter.heroku.com/articles/using-terraform-with-heroku).
The Heroku Terraform scripts are in the [terraform/heroku folder](./terraform/heroku).
A [util script](./bin/uptermd-install) is provided for your convenience to automate everything:

```
$ git clone https://github.com/jingweno/upterm
$ cd upterm

# Provinsion uptermd in Heroku Common Runtime.
# Follow instructions
$ bin/uptermd-install 

# Provinsion uptermd in Heroku Private Spaces.
# Follow instructions
$ TF_VAR_heroku_region=REGION TF_VAR_heroku_space=SPACE_NAME TF_VAR_heroku_team=TEAM_NAME bin/uptermd-install
```

You must use WebScoket as the protocol for a Heroku-deployed Uptermd server. This is how you host a session and join a session:

```
# Use the Heroku-deployed Uptermd server via WebSocket
$ upterm host --server wss://YOUR_HEROKU_APP_URL -- YOUR_COMMAND

# A client connects to the host session via WebSocket
$ ssh -o ProxyCommand='upterm proxy wss://TOKEN@YOUR_HEROKU_APP_URL' TOKEN@YOUR_HEROKU_APP_URL:443
```

## License

[Apache 2.0](https://github.com/jingweno/upterm/blob/master/LICENSE)
