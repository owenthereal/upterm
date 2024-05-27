# Upterm

[Upterm](https://github.com/owenthereal/upterm) is an open-source tool enabling developers to share terminal sessions securely over the web. It’s perfect for remote pair programming, accessing computers behind NATs/firewalls, remote debugging, and more.

This is a [blog post](https://owenou.com/upterm) to describe Upterm in depth.

## :movie_camera: Quick Demo

[![demo](https://raw.githubusercontent.com/owenthereal/upterm/gh-pages/demo.gif)](https://asciinema.org/a/efeKPxxzKi3pkyu9LWs1yqdbB)

## :rocket: Getting Started

## Installation

### Mac

```console
brew install owenthereal/upterm/upterm
```

### Standalone

`upterm` can be easily installed as an executable. Download the latest [compiled binaries](https://github.com/owenthereal/upterm/releases) and put it in your executable path.

### From source

```console
git clone git@github.com:owenthereal/upterm.git
cd upterm
go install ./cmd/upterm/...
```

## :wrench: Basic Usage

1. Host starts a terminal session:

```console
upterm host
```

2. Host retrieves and shares the SSH connection string:

```console
upterm session current
```

3. Client connects using the shared string:

```console
ssh TOKEN@uptermd.upterm.dev
```

## :blue_book: Quick Reference

Dive into more commands and advanced usage in the [documentation](docs/upterm.md).
Below are some notable highlights:

### Command Execution

Host a session with any desired command:

```console
upterm host -- docker run --rm -ti ubuntu bash
```

### Access Control

Host a session with specified client public key(s) authorized to connect:

```console
upterm host --authorized-key PATH_TO_PUBLIC_KEY
```

Authorize specified GitHub, GitLab, SourceHut, Codeberg users with their corresponding public keys:

```console
upterm host --github-user username
upterm host --gitlab-user username
upterm host --srht-user username
upterm host --codeberg-user username
```

### Force command

Host a session initiating `tmux new -t pair-programming`, while ensuring clients join with `tmux attach -t pair-programming`.
This mirrors functionarity provided by tmate:

```console
upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming
```

### WebSocket Connection

In scenarios where your host restricts ssh transport, establish a connection to `uptermd.upterm.dev` (or your self-hosted server) via WebSocket:

```console
upterm host --server wss://uptermd.upterm.dev -- bash
```

Clients can connect to the host session via WebSocket as well:

```console
ssh -o ProxyCommand='upterm proxy wss://TOKEN@uptermd.upterm.dev' TOKEN@uptermd.upterm.dev:443
```

### Debug GitHub Actions

`upterm` can be integrated with GitHub Actions to enable real-time SSH debugging, allowing you to interact directly with the runner system during workflow execution. This is achieved through [action-upterm](https://github.com/owenthereal/action-upterm), which sets up an `upterm` session within your CI pipeline.

To get started, include `action-upterm` in your GitHub Actions workflow as follows:

```yaml
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup upterm session
      uses: owenthereal/action-upterm@v1
```

This setup allows you to SSH into the workflow runner whenever you need to troubleshoot or inspect the execution environment. Find the SSH connection string in the `Checks` tab of your Pull Request or in the workflow logs.

For comprehensive details on configuring and using this integration, visit the [action-upterm GitHub repo](https://github.com/owenthereal/action-upterm).

## :bulb: Tips

### Resolving Tmux Session Display Issue

**Issue**: The command `upterm session current` does not display the current session when used within Tmux.

**Cause**: This occurs because `upterm session current` requires the `UPTERM_ADMIN_SOCKET` environment variable, which is set in the specified command. Tmux, however, does not carry over environment variables not on its default list to any Tmux session unless instructed to do so ([Reference](http://man.openbsd.org/i386/tmux.1#GLOBAL_AND_SESSION_ENVIRONMENT)).

**Solution**: To rectify this, add the following line to your `~/.tmux.conf`:

```conf
set-option -ga update-environment " UPTERM_ADMIN_SOCKET"
```

### Identifying Upterm Session

**Issue**: It might be unclear whether your shell command is running in an upterm session, especially with common shell commands like `bash` or `zsh`.

**Solution**: To provide a clear indication, amend your `~/.bashrc` or `~/.zshrc` with the following line. This decorates your prompt with an emoji whenever the shell command is running in an upterm session:

```bash
export PS1="$([[ ! -z "${UPTERM_ADMIN_SOCKET}"  ]] && echo -e '\xF0\x9F\x86\x99 ')$PS1" # Add an emoji to the prompt if `UPTERM_ADMIN_SOCKET` exists
```

## :gear: How it works

Upterm starts an SSH server (a.k.a. `sshd`) in the host machine and sets up a reverse SSH tunnel to a [Upterm server](https://github.com/owenthereal/upterm/tree/master/cmd/uptermd) (a.k.a. `uptermd`).
Clients connect to a terminal session over the public internet via `uptermd` using `ssh` or `ssh` over WebSocket.

![upterm flowchart](https://raw.githubusercontent.com/owenthereal/upterm/gh-pages/upterm-flowchart.svg?sanitize=true)

## :hammer_and_wrench: Deployment

### Kubernetes

You can deploy uptermd to a Kubernetes cluster. Install it with [helm](https://helm.sh):

```console
helm repo add upterm https://upterm.dev
helm repo update
helm install uptermd upterm/uptermd
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
git clone https://github.com/owenthereal/upterm
cd upterm
```

Provision uptermd in Heroku Common Runtime. Follow instructions.

```console
bin/heroku-install
```

Provision uptermd in Heroku Private Spaces. Follow instructions.

```console
TF_VAR_heroku_region=REGION TF_VAR_heroku_space=SPACE_NAME TF_VAR_heroku_team=TEAM_NAME bin/heroku-install
```

You **must** use WebScoket as the protocol for a Heroku-deployed Uptermd server because the platform only support HTTP/HTTPS routing.
This is how you host a session and join a session:

Use the Heroku-deployed Uptermd server via WebSocket

```console
upterm host --server wss://YOUR_HEROKU_APP_URL -- YOUR_COMMAND
```

A client connects to the host session via WebSocket

```console
ssh -o ProxyCommand='upterm proxy wss://TOKEN@YOUR_HEROKU_APP_URL' TOKEN@YOUR_HEROKU_APP_URL:443
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
cp systemd/uptermd.service /etc/systemd/system/uptermd.service
systemctl daemon-reload
systemctl start uptermd
```

## :balance_scale: Comparasion with Prior Arts

Upterm stands as a modern alternative to [Tmate](https://tmate.io).

Tmate originates as a fork from an older iteration of Tmux, extending terminal sharing capabilities atop Tmux 2.x. However, Tmate has no plans to align with the latest Tmux updates, compelling Tmate & Tmux users to manage two separate configurations. For instance, the necessity to [bind identical keys twice, conditionally](https://github.com/tmate-io/tmate/issues/108).

On the flip side, Upterm is architected from the ground up to be an independent solution, not a fork. It embodies the idea of connecting the input & output of any shell command between a host and its clients, transcending beyond merely `tmux`. This paves the way for securely sharing terminal sessions utilizing containers.

Written in Go, Upterm is more hack-friendly compared to Tmate, which is crafted in C, akin to Tmux. The seamless compilation of Upterm CLI and server (`uptermd`) into a single binary facilitates swift [deployment of your pairing server](#hammer_and_wrench-deployment) across any cloud environment, devoid of dependencies.

## License

[Apache 2.0](https://github.com/owenthereal/upterm/blob/master/LICENSE)
