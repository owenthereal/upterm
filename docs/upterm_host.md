## upterm host

Host a terminal session

### Synopsis

Host a terminal session via a reverse SSH tunnel to the Upterm server.

The session links the host and client IO to a command's IO. Authentication with the
Upterm server uses, in this order:
  1. SSH agent keys, when an agent is running and holds any
  2. Private key files: ~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}
  3. Auto-generated ephemeral key, when neither is available

Supplying --private-key makes the named list the whole set instead; see its help.

To authorize client connections, use --authorized-keys to specify an authorized_keys file
containing client public keys.

The session runs in a process of its own. This terminal is a client of it:
type ~. at the start of a line (or --escape-char) to leave the session
running, reattach with 'upterm attach NAME', and end it with
'upterm session stop NAME'. With --detach nothing is attached: the session
starts in the background and this command prints how to reach it.

```
upterm host [flags]
```

### Examples

```
  # Host a terminal session running $SHELL, attaching client's IO to the host's:
  upterm host

  # Accept client connections automatically without prompts:
  upterm host --accept

  # Host a terminal session allowing only specified public key(s) to connect:
  upterm host --authorized-keys PATH_TO_AUTHORIZED_KEY_FILE

  # Authorize a user by fetching their public keys from a code-hosting service:
  upterm host --authorized-user github:username

  # Host a session executing a custom command:
  upterm host -- docker run --rm -ti ubuntu bash

  # Host a 'tmux new -t pair-programming' session, forcing clients to join with 'tmux attach -t pair-programming':
  upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming

  # Allow clients to use local TCP forwarding (ssh -L) through the hosted session:
  upterm host --allow-local-tcp-forwarding

  # Use a different Uptermd server, hosting a session via WebSocket:
  upterm host --server wss://YOUR_UPTERMD_SERVER -- YOUR_COMMAND

  # Start a session in the background and print how to reach it:
  upterm host --detach --accept --github-user alice

  # The same, as JSON for a script:
  upterm host --detach --accept --github-user alice -o json
```

### Options

```
      --accept                       Automatically accept client connections without prompts.
      --allow-local-tcp-forwarding   Allow clients to use SSH local TCP forwarding (ssh -L) through the hosted session, reaching TCP destinations visible to the host.
      --authorized-keys string       Specify a authorize_keys file listing authorized public keys for connection.
      --authorized-user strings      Authorize users by fetching their public keys from a code-hosting service. Repeatable. Providers: github, gitlab, codeberg, srht (host optional), gitea, forgejo (host required). Examples: github:alice, github:bob@ghe.example.com, gitea:carol@git.example.com, https://git.example.com/dave
      --detach                       Start the session in the background and exit once it is running. Requires --accept. Attach a terminal later with 'upterm attach NAME'; stop it with 'upterm session stop NAME'.
      --escape-char string           Escape character for detaching this terminal from the session (ESC-CHAR followed by . at the start of a line), or 'none' to disable. No effect where the session runs in this process (Windows, until spawning lands there): the only terminal there is the session's own. (default "~")
  -f, --force-command string         Enforce a specified command for clients to join, and link the command's input/output to the client's terminal.
  -h, --help                         help for host
      --hide-client-ip               Hide client IP addresses from output (auto-enabled in CI environments).
      --known-hosts string           Specify a file containing known keys for remote hosts (required). (default "~/.ssh/known_hosts")
      --name string                  Name this session. Determines the socket paths, so it can be looked up with 'upterm session info NAME'. Defaults to COMMAND-XXXX.
      --no-sftp                      Disable file transfer via SFTP/SCP. By default, clients can transfer files with the same access as the terminal session.
  -o, --output string                With --detach, print the started session as JSON (the same shape as 'upterm session info NAME -o json').
  -i, --private-key strings          Identity files for authenticating with the upterm server. Supplying this makes the list the whole set, like OpenSSH's IdentitiesOnly: each file must load, a .pub selects that key in the SSH agent, and other agent keys are not offered. By default, the agent's keys are used when it has any, then the listed files that exist, then a generated key. (default [~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}])
      --proxy string                 HTTP proxy to connect to the server through (e.g. http://proxy.example.com:3128). Works with ssh, ws, and wss servers. Without it, ws and wss connections use HTTPS_PROXY/HTTP_PROXY and ssh connections go direct.
      --pty-size string              Pin the session's terminal size as COLSxROWS (e.g. 132x43). Client resize requests are then ignored. Defaults to the attached terminal's size, or 80x24 when there is none.
  -r, --read-only                    Host a read-only session, preventing client interaction. Also restricts SFTP to download-only.
      --server string                Specify the upterm server address (required). Supported protocols: ssh, ws, wss. (default "ssh://uptermd.upterm.dev:22")
      --skip-host-key-check          Automatically accept unknown server host keys and add them to known_hosts (similar to SSH's StrictHostKeyChecking=accept-new). This bypasses host key verification for new connections.
      --term string                  Set TERM for the hosted command. Defaults to the inherited TERM, or xterm-256color when TERM is unset or dumb.
```

### Options inherited from parent commands

```
      --debug   enable debug level logging (log file: /home/user/.local/state/upterm/upterm.log).
```

### SEE ALSO

* [upterm](upterm.md)	 - Instant Terminal Sharing

###### Auto generated by spf13/cobra on 19-Sep-2026
