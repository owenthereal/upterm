# Upterm

[Upterm](https://github.com/jingweno/upterm) is an open-source solution for sharing terminal sessions instantly over the public internet via secure tunnels.
Upterm is good for

* Remote pair programming
* Access remote computers behind NATs and firewalls
* Remote debugging
* \<insert your creative use cases\>

## Usage

The host starts a terminal session:

```bash
$ upterm host -- bash
```

The host displays the ssh connection string:

```bash
$ upterm session current
=== IQKSFOICLSNNXQZTDKOJ
Command:                bash
Force Command:          n/a
Host:                   ssh://uptermd.upterm.dev:22
SSH Session:            ssh IqKsfoiclsNnxqztDKoj:MTAuMC40OS4xNjY6MjI=@uptermd.upterm.dev
```

The client opens a terminal and connects to the host's session:

```bash
$ ssh IqKsfoiclsNnxqztDKoj:MTAuMC40OS4xNjY6MjI=@uptermd.upterm.dev
```

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

## Upgrade

`upterm` comes with a command to upgrade

```bash
$ upterm upgrade # upgrade to the latest version

$ upterm upgrade VERSION # upgrade to a version
```

### Mac

```
brew upgrade upterm
```

## Quick Reference

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

# Host a terminal session that only allows specified client public key(s) to connect
$ upterm host --authorized-key PATH_TO_PUBLIC_KEY

# Host a session with a custom command
$ upterm host -- docker run --rm -ti ubuntu bash

# Host a session that runs 'tmux new -t pair-programming' and
# force clients to join with 'tmux attach -t pair-programming'.
# This is similar to what tmate offers.
$ upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming`,

# Connect to uptermd.upterm.dev via WebSocket
$ upterm host --server wss://uptermd.upterm.dev -- bash

# A client connects to the host session via WebSocket
$ ssh -o ProxyCommand='upterm proxy wss://TOKEN@uptermd.upterm.dev' TOKEN@uptermd.upterm.dev:443
```

More advanced usage is [here](https://github.com/jingweno/upterm/blob/master/docs/upterm.md).

## Tips

**Why doesn't `upterm session current` show current session in Tmux?**

`upterm session current` needs the `UPTERM_ADMIN_SOCKET` environment variable to function.
And this env var is set in the specified command.
Unfotunately, Tmux doesn't carry over environment variables that are not in its default list to any Tmux session unless you tell it to ([Ref](http://man.openbsd.org/i386/tmux.1#GLOBAL_AND_SESSION_ENVIRONMENT)).
So to get `upterm session current` to work, add the following line to your `~/.tmux.conf`

```conf
set-option -ga update-environment " UPTERM_ADMIN_SOCKET"
```

**How to make it obvious that I am in an upterm session?**

It can be confusing whether your shell command is running in an upterm session or not, especially if the shell command is `bash` or `zsh`.
Add the following line to your `~/.bashrc` or `~/.zshrc` and decorate your prompt to show a sign if the shell command is in a terminal session:

```bash
export PS1="$([[ ! -z "${UPTERM_ADMIN_SOCKET}"  ]] && echo -e '\xF0\x9F\x86\x99 ')$PS1" # Add an emoji to the prompt if `UPTERM_ADMIN_SOCKET` exists
```

## Demo

[![asciicast](https://asciinema.org/a/LTwpMqvvV98eo3ueZHoifLHf7.svg)](https://asciinema.org/a/LTwpMqvvV98eo3ueZHoifLHf7)

## How it works

You run the `upterm` program by specifying the command for your terminal session.
Upterm starts an SSH server (a.k.a. `sshd`) in the host machine and sets up a reverse SSH tunnel to a [Upterm server](https://github.com/jingweno/upterm/tree/master/cmd/uptermd) (a.k.a. `uptermd`).
Clients connect to your terminal session over the public internet via `uptermd` using `ssh` using TCP or WebSocket.
A community Upterm server is running at `uptermd.upterm.dev` and `upterm` points to this server by default.

![upterm flowchart](https://raw.githubusercontent.com/jingweno/upterm/gh-pages/upterm-flowchart.svg?sanitize=true)

## Deploy Uptermd

The easiest and the cheapest way to deploy a [Upterm server](https://github.com/jingweno/upterm/tree/master/cmd/uptermd) (a.k.a. `uptermd`) is to use [Heroku](https://heroku.com).
Heroku offers [free Dyno hours](https://www.heroku.com/pricing) which should be sufficient for most casual uses.

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

You **must** use WebScoket as the protocol for a Heroku-deployed Uptermd server because the platform only support HTTP/HTTPS routing.
This is how you host a session and join a session:

```
# Use the Heroku-deployed Uptermd server via WebSocket
$ upterm host --server wss://YOUR_HEROKU_APP_URL -- YOUR_COMMAND

# A client connects to the host session via WebSocket
$ ssh -o ProxyCommand='upterm proxy wss://TOKEN@YOUR_HEROKU_APP_URL' TOKEN@YOUR_HEROKU_APP_URL:443
```

## License

[Apache 2.0](https://github.com/jingweno/upterm/blob/master/LICENSE)
