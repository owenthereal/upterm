# Upterm

[Upterm](https://github.com/owenthereal/upterm) is an open-source solution for sharing terminal sessions instantly over the public internet via secure tunnels.
Upterm is good for

* Remote pair programming
* Access remote computers behind NATs and firewalls
* Remote debugging
* \<insert your creative use cases\>

This is a [blog post](https://owenou.com/upterm) to describe Upterm in depth.

## Usage

The host starts a terminal session:

```console
$ upterm host -- bash
```

The host displays the ssh connection string:

```console
$ upterm session current
=== IQKSFOICLSNNXQZTDKOJ
Command:                bash
Force Command:          n/a
Host:                   ssh://uptermd.upterm.dev:22
SSH Session:            ssh IqKsfoiclsNnxqztDKoj:MTAuMC40OS4xNjY6MjI=@uptermd.upterm.dev
```

The client opens a terminal and connects to the host's session:

```console
$ ssh IqKsfoiclsNnxqztDKoj:MTAuMC40OS4xNjY6MjI=@uptermd.upterm.dev
```

## Installation

### Mac

```console
$ brew install owenthereal/upterm/upterm
```

### Standalone

`upterm` can be easily installed as an executable. Download the latest [compiled binaries](https://github.com/owenthereal/upterm/releases) and put it in your executable path.

### From source

```console
$ git clone git@github.com:owenthereal/upterm.git
$ cd upterm
$ go install ./cmd/upterm/...
```

## Upgrade

`upterm` comes with a command to upgrade

Upgrade to the latest version
```console
$ upterm upgrade
```

Upgrade to a specific version
```console
$ upterm upgrade VERSION
```

### Mac

```console
$ brew upgrade upterm
```

## Quick Reference

Host a terminal session that runs `$SHELL` with client's input/output attaching to the host's
```console
$ upterm host
```

Display the ssh connection string and share it with the client(s)
```console
$ upterm session current
=== SESSION_ID
Command:                /bin/bash
Force Command:          n/a
Host:                   ssh://uptermd.upterm.dev:22
SSH Session:            ssh TOKEN@uptermd.upterm.dev
```

A client connects to the host session with `ssh`
```console
$ ssh TOKEN@uptermd.upterm.dev
```

Host a terminal session that only allows specified client public key(s) to connect
```console
$ upterm host --authorized-key PATH_TO_PUBLIC_KEY
```

Host a terminal session that only allows specified GitHub user client public key(s) to connect.
This is compatible with `--authorized-keys`.
```console
$ upterm host --github-user username
```

Host a terminal session that only allows specified GitLab user client public key(s) to connect. 
This is compatible with `--authorized-keys`.
```console
$ upterm host --gitlab-user username
```

Host a session with a custom command
```console
$ upterm host -- docker run --rm -ti ubuntu bash
```

Host a session that runs 'tmux new -t pair-programming' and force clients to join with `tmux attach -t pair-programming`.
Copy the SSH Session url and press enter before sharing the url with your peer.
This is similar to what tmate offers.
```console
$ upterm host --force-command 'tmux attach -t pair-programming' -- bash -c "read -p 'Press enter to continue ' && tmux new -t pair-programming"
```

Connect to uptermd.upterm.dev via WebSocket
```console
$ upterm host --server wss://uptermd.upterm.dev -- bash
```

A client connects to the host session via WebSocket
```console
$ ssh -o ProxyCommand='upterm proxy wss://TOKEN@uptermd.upterm.dev' TOKEN@uptermd.upterm.dev:443
```

More advanced usage is [here](https://github.com/owenthereal/upterm/blob/master/docs/upterm.md).

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
Upterm starts an SSH server (a.k.a. `sshd`) in the host machine and sets up a reverse SSH tunnel to a [Upterm server](https://github.com/owenthereal/upterm/tree/master/cmd/uptermd) (a.k.a. `uptermd`).
Clients connect to your terminal session over the public internet via `uptermd` using `ssh` using TCP or WebSocket.
A community Upterm server is running at `uptermd.upterm.dev` and `upterm` points to this server by default.

![upterm flowchart](https://raw.githubusercontent.com/owenthereal/upterm/gh-pages/upterm-flowchart.svg?sanitize=true)

## A note about RSA keys

Since openssh 8.8 (2021-09-26), the host algorithm type SHA-1 (`ssh-rsa`) was retired in favor of SHA-2 (`rsa-sha2-256` or `rsa-sha2-512`) ([release note](https://www.openssh.com/txt/release-8.8)).
Unfortunately, due to a shortcoming in Go’s `x/crypto/ssh` package, `upterm` does not completely support SSH clients using SHA-2 keys: only the old SHA-1 ones will work.

You can check your `openssh` version with the following:

```console
$ ssh -V
```

If you are not sure what type of keys you have, you can check with the following:

```console
$ find ~/.ssh/id_*.pub -exec ssh-keygen -l -f {} \;
```

Until this is sorted out, you are recommended to use key with another algorithm, e.g. Ed25519.

If you're curious about the inner workings of this problem, have a look at:

- https://github.com/owenthereal/upterm/issues/93#issuecomment-1045387517
- https://github.com/golang/go/issues/49952

## Deploy Uptermd

### Kubernetes

You can deploy uptermd to a Kubernetes cluster. Install it with [helm](https://helm.sh):

```console
$ helm repo add upterm https://upterm.dev
$ helm repo update
$ helm search repo upterm
NAME            CHART VERSION   APP VERSION     DESCRIPTION
upterm/uptermd  0.1.0           0.4.1           Secure Terminal Sharing
$ helm install uptermd upterm/uptermd
```

### Heroku

The cheapest way to deploy a worry-free [Upterm server](https://github.com/owenthereal/upterm/tree/master/cmd/uptermd) (a.k.a. `uptermd`) is to use [Heroku](https://heroku.com).
Heroku offers [free Dyno hours](https://www.heroku.com/pricing) which should be sufficient for most casual uses.

You can deploy with one click of the following button:

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

You can also automate the deployment with [Heroku Terraform](https://devcenter.heroku.com/articles/using-terraform-with-heroku).
The Heroku Terraform scripts are in the [terraform/heroku folder](./terraform/heroku).
A [util script](./bin/heroku-install) is provided for your convenience to automate everything:

```console
$ git clone https://github.com/owenthereal/upterm
$ cd upterm
```

Provision uptermd in Heroku Common Runtime. Follow instructions.
```console
$ bin/heroku-install
```

Provision uptermd in Heroku Private Spaces. Follow instructions.
```console
$ TF_VAR_heroku_region=REGION TF_VAR_heroku_space=SPACE_NAME TF_VAR_heroku_team=TEAM_NAME bin/heroku-install
```

You **must** use WebScoket as the protocol for a Heroku-deployed Uptermd server because the platform only support HTTP/HTTPS routing.
This is how you host a session and join a session:

Use the Heroku-deployed Uptermd server via WebSocket
```console
$ upterm host --server wss://YOUR_HEROKU_APP_URL -- YOUR_COMMAND
```

A client connects to the host session via WebSocket
```console
$ ssh -o ProxyCommand='upterm proxy wss://TOKEN@YOUR_HEROKU_APP_URL' TOKEN@YOUR_HEROKU_APP_URL:443
```

### Digital Ocean

There is an util script that makes provisioning [Digital Ocean Kubernetes](https://www.digitalocean.com/products/kubernetes) and an Upterm server easier:

```bash
TF_VAR_do_token=$DO_PAT \
TF_VAR_uptermd_host=uptermd.upterm.dev \
TF_VAR_uptermd_acme_email=YOUR_EMAIL \
TF_VAR_uptermd_helm_repo=http://localhost:8080 \
TF_VAR_uptermd_host_keys_dir=PATH_TO_HOST_KEYS \
bin/do-install
```

### Systemd

A hardened systemd service is provided in `systemd/uptermd.service`. You can use it to easily run a
secured `uptermd` on your machine:

```console
$ cp systemd/uptermd.service /etc/systemd/system/uptermd.service
$ systemctl daemon-reload
$ systemctl start uptermd
```

## How is Upterm compared to prior arts?

Upterm is an alternative to [Tmate](https://tmate.io).

Tmate is a fork of an older version of Tmux. It adds terminal sharing capability on top of Tmux 2.x.
Tmate doesn't intend to catch up with the latest Tmux, so any Tmate & Tmux users must maintain two versions of the configuration.
For example, you must [bind the same keys twice with a condition](https://github.com/tmate-io/tmate/issues/108).

Upterm is designed from the group up not to be a fork of anything.
It builds around the concept of linking the input & output of any shell command between a host and its clients.
As you see above, you can share any command besides `tmux`.
This opens up a door for securely sharing a terminal session using containers.

Upterm is written in Go.
It is more friendly hackable than Tmate that is written in C because Tmux is C.
The Upterm CLI and server (`uptermd`) are compiled into a single binary.
You can quickly [spawn up your pairing server](#deploy-uptermd) in any cloud environment with zero dependencies.

## License

[Apache 2.0](https://github.com/owenthereal/upterm/blob/master/LICENSE)
