## upterm ci

Host a debugging session from a CI job

### Synopsis

Host a terminal session on a CI runner and tell the CI system how to join it.

This is 'upterm host' with the defaults a CI job needs and a lifecycle suited to
one. There is no terminal on a runner and nobody watching the build log as it
scrolls, so the session:

  * accepts clients without an interactive prompt,
  * publishes the SSH command the way the CI system expects (on GitHub Actions:
    the 'ssh-command' step output, the job summary, and a notice annotation),
  * shuts down on its own if nobody connects within --wait-timeout, so an
    unanswered session does not hold the runner for the job's whole timeout,
  * keeps the session's own terminal output out of the job log, which on a
    public repository is public (--log-session-output puts it back),
  * ends when a 'continue' file appears, which is how someone inside the
    session hands the job back.

Once a client connects, --wait-timeout no longer applies: the session stays up
until the shell exits, the continue file appears, or the job is cancelled.

Restrict who may join with --limit-access-to-actor and --limit-access-to-users,
or with any of 'upterm host's own --authorized-user and --authorized-keys flags.
Without one of those, anyone holding the session's SSH command can join, and on
a public repository that command is in a public build log.

```
upterm ci [flags]
```

### Examples

```
  # Debug a GitHub Actions job, letting only the user who triggered it in:
  upterm ci --limit-access-to-actor

  # Let a named set of GitHub users in, and wait half an hour for one of them:
  upterm ci --limit-access-to-users alice,bob --wait-timeout 30m

  # Hand the job back from inside the session:
  $ touch /continue

  # Use your own upterm server:
  upterm ci --server wss://YOUR_UPTERMD_SERVER --limit-access-to-actor
```

### Options

```
      --allow-local-tcp-forwarding      Allow clients to use SSH local TCP forwarding (ssh -L) through the hosted session, reaching TCP destinations visible to the host.
      --authorized-keys string          Specify a authorize_keys file listing authorized public keys for connection.
      --authorized-user strings         Authorize users by fetching their public keys from a code-hosting service. Repeatable. Providers: github, gitlab, codeberg, srht (host optional), gitea, forgejo (host required). Examples: github:alice, github:bob@ghe.example.com, gitea:carol@git.example.com, https://git.example.com/dave
      --continue-file string            End the session when this file appears. Defaults to /continue and $GITHUB_WORKSPACE/continue.
  -f, --force-command string            Enforce a specified command for clients to join, and link the command's input/output to the client's terminal.
  -h, --help                            help for ci
      --hide-client-ip                  Hide client IP addresses from output (auto-enabled in CI environments).
      --known-hosts string              Specify a file containing known keys for remote hosts (required). (default "~/.ssh/known_hosts")
      --limit-access-to-actor           Authorize only the account that triggered the CI job, by fetching its public keys from the CI system's code host.
      --limit-access-to-users strings   Authorize only these GitHub users, by fetching their public keys. Repeatable, and accepts a comma- or whitespace-separated list.
      --log-session-output              Mirror the session's terminal output into the CI job log. Off by default: that log may be public and outlives the run.
      --name string                     Name this session. Determines the socket paths, so it can be looked up with 'upterm session info NAME'. Defaults to COMMAND-XXXX.
      --no-sftp                         Disable file transfer via SFTP/SCP. By default, clients can transfer files with the same access as the terminal session.
  -i, --private-key strings             Specify private key files for public key authentication with the upterm server (required). Only existing files are included by default. (default [~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}])
      --proxy string                    HTTP proxy to connect to the server through (e.g. http://proxy.example.com:3128). Works with ssh, ws, and wss servers. Without it, ws and wss connections use HTTPS_PROXY/HTTP_PROXY and ssh connections go direct.
      --pty-size string                 Pin the session's terminal size as COLSxROWS (e.g. 132x43). Client resize requests are then ignored. Defaults to the host terminal's size, or 80x24 when there is none.
  -r, --read-only                       Host a read-only session, preventing client interaction. Also restricts SFTP to download-only.
      --server string                   Specify the upterm server address (required). Supported protocols: ssh, ws, wss. (default "ssh://uptermd.upterm.dev:22")
      --skip-host-key-check             Automatically accept unknown server host keys and add them to known_hosts (similar to SSH's StrictHostKeyChecking=accept-new). This bypasses host key verification for new connections. (default true)
      --term string                     Set TERM for the hosted command. Defaults to the inherited TERM, or xterm-256color when TERM is unset or dumb.
      --wait-timeout duration           Shut down the session if no client has connected within this long. 0 waits forever. (default 10m0s)
```

### Options inherited from parent commands

```
      --debug   enable debug level logging (log file: /home/user/.local/state/upterm/upterm.log).
```

### SEE ALSO

* [upterm](upterm.md)	 - Instant Terminal Sharing

###### Auto generated by spf13/cobra on 15-Sep-2026
