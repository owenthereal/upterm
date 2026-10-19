## upterm host

Host a terminal session

### Synopsis

Host a terminal session: run COMMAND, or $SHELL without one, and share it
through a relay, so that guests can join it from their own terminals with
upterm join or plain ssh.

upterm prints the session, with the commands guests join it with, and asks
before starting it; --accept starts it without asking. The relay is
--server, and upterm authenticates to it with the first of these it has:
  1. The SSH agent's keys, when an agent is running and holds any
  2. Otherwise, the private key files that load: ~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}
  3. Otherwise, a generated key

Supplying --private-key makes the named list the whole set instead; see its
help.

Who can join: anyone with the session's connect string, unless
--authorized-keys (an authorized_keys file) or --authorized-user names the
keys a guest must have.

What guests may do: type into the session, or only watch it with
--read-only; transfer files with sftp or scp, with your access (downloads
only with --read-only, none with --no-sftp); and forward TCP ports (ssh -L)
to what this machine can reach, only with --allow-local-tcp-forwarding.
Unless --accept, a guest's file transfers need your approval in a desktop
dialog on this machine, which can allow the file asked about, or everything
in that scp or sftp command; where no dialog can be shown, transfers are
denied.

The session runs in a process of its own, and this terminal is attached to
it. NAME is the session's name, which upterm prints (--name chooses it).

Keys, at the start of a line (--escape-char changes the ~, or turns them off):
  ~.    detach: the session keeps running; 'upterm attach NAME' reattaches
        and 'upterm session stop NAME' ends it
  ~?    show the session's status and keys, in this terminal only; the
        program may need its own redraw afterwards
  ~^Z   suspend this terminal (Unix); fg resumes it
  ~~    send a ~

Through an outer ssh connection, ssh's own ~ escapes come first: type ~~.,
~~? and ~~^Z, or connect with 'ssh -e none' and type them plain.

On Unix you can also suspend with ~^Z, run 'upterm session info NAME', and
return with fg. A session that keeps producing output while this terminal
is suspended may disconnect it (254 below); 'upterm attach NAME' brings it
back.

With --detach nothing is attached: the session starts in the background, and
upterm prints how to reach it.

Exit status: the command's own status when it exits; 1 when upterm fails, or
the session is stopped or ends by a signal (whatever the command returns
while it is torn down); 254 when this terminal is disconnected; 130 for
Ctrl-C at a prompt, 143 for a SIGTERM there; 0 after declining at the prompt
or detaching (~.). A command's own 1 or 254 reads the same. With --detach: 0
once the session has started, 1 when it can't start; upterm session wait NAME
reports the command's status.

```
upterm host [flags] [-- COMMAND [ARGS...]]
```

### Examples

```
  # Host $SHELL; upterm prints how guests join it:
  upterm host

  # Host a command:
  upterm host -- docker run --rm -ti ubuntu bash

  # Let only the keys alice has on GitHub join:
  upterm host --authorized-user github:alice

  # Let only the keys in an authorized_keys file join:
  upterm host --authorized-keys ~/.ssh/guests_authorized_keys

  # Start without asking, and let guests transfer files without approval:
  upterm host --accept

  # Host 'tmux new -t pair-programming', and give each guest
  # 'tmux attach -t pair-programming' instead of the session itself:
  upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming

  # Let guests forward TCP ports (ssh -L) to what this machine can reach:
  upterm host --allow-local-tcp-forwarding

  # Host on another relay, over a WebSocket:
  upterm host --server wss://relay.example.com

  # Start a session in the background and print how to reach it:
  upterm host --detach --accept --authorized-user github:alice

  # The same, as JSON for a script:
  upterm host --detach --accept --authorized-user github:alice -o json
```

### Options

```
      --accept                       Start the session without asking, and let guests transfer files without your approval. Without it, a guest's file transfers need your approval in a desktop dialog on this machine, which can allow the file asked about, or everything in that scp or sftp command; where no dialog can be shown, transfers are denied.
      --allow-local-tcp-forwarding   Let guests forward TCP ports (ssh -L) through the session, to whatever this machine can reach. Can't be used with --read-only.
      --authorized-keys string       An authorized_keys file: only guests with a key it lists, or that --authorized-user names, can join.
      --authorized-user strings      Let a user join with the public keys a code-hosting service lists for them, fetched through --proxy when it is set. Repeatable. Providers: github, gitlab, codeberg, srht (host optional), gitea, forgejo (host required). Examples: github:alice, github:bob@ghe.example.com, gitea:carol@git.example.com, https://git.example.com/dave
      --detach                       Start the session in the background and exit once it is running. Requires --accept. Attach a terminal later with 'upterm attach NAME'; stop it with 'upterm session stop NAME'.
      --escape-char string           The character that starts upterm's keys at the start of a line, or 'none' to turn them off. (default "~")
  -f, --force-command string         Run this command for each guest who joins, on a terminal of its own, instead of showing them the session's command (e.g. 'tmux attach -t pair-programming', for a tmux session of that name).
  -h, --help                         help for host
      --hide-client-ip               Hide guests' IP addresses from upterm's output, and from forced commands' SSH_CONNECTION and SSH_CLIENT. When it isn't set (by flag, environment or config file), they are hidden in CI only; --hide-client-ip=false shows them there too.
      --join-timeout duration        End the session if no guest has joined within this long (e.g. 10m). 0 waits forever. A guest who joins disarms it permanently, so a guest who joins and then leaves does not re-arm it. Change it later with 'upterm session set NAME --join-timeout'.
      --known-hosts string           Known keys of relays. An unknown relay key is shown for confirmation, as ssh does. (default "~/.ssh/known_hosts")
      --name string                  Name the session, for upterm attach and the session commands to find it by. Defaults to the command's name and four hex digits, e.g. bash-1f3a.
      --no-sftp                      Turn off file transfer (sftp and scp) for guests. Without it, guests transfer files with your access (downloads only with --read-only), and unless --accept, a guest's file transfers need your approval in a desktop dialog on this machine, which can allow the file asked about, or everything in that scp or sftp command; where no dialog can be shown, transfers are denied.
  -o, --output string                With --detach, print the started session as JSON: a superset of the fields 'upterm session info NAME -o json' reports at launch, with sshCommand and joinCommand present even when its status says guests can't join.
  -i, --private-key strings          Identity files to authenticate to the relay with. Supplying this makes the list the whole set, like OpenSSH's IdentitiesOnly: each file must load, a public key (.pub) file selects that key in the SSH agent, and other agent keys are not offered. By default it offers the agent's keys alone when the agent holds any, and otherwise the listed files that load, or a generated key when none do. (default [~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}])
      --proxy string                 HTTP proxy to reach the relay through (e.g. http://proxy.example.com:3128). Works with ssh, ws and wss relays. Without it, ws and wss use HTTPS_PROXY/HTTP_PROXY, and ssh goes direct.
      --pty-size string              Pin the session's terminal size as COLSxROWS (e.g. 132x43); resize requests are then ignored. Defaults to the attached terminal's size, or 80x24 when there is none.
  -r, --read-only                    Let guests only watch: they can't type into the session, and can only download files. Unless --accept, a guest's file transfers need your approval in a desktop dialog on this machine, which can allow the file asked about, or everything in that scp or sftp command; where no dialog can be shown, transfers are denied. Can't be used with --allow-local-tcp-forwarding.
      --server string                Relay to host the session on: ssh://HOST[:PORT], ws://HOST[:PORT] or wss://HOST[:PORT]. Without a port, ssh uses 22, ws 80 and wss 443. (default "ssh://uptermd.upterm.dev:22")
      --skip-host-key-check          Accept an unknown relay key and record it without asking (similar to SSH's StrictHostKeyChecking=accept-new). A changed key is still refused.
      --term string                  Set TERM for the hosted command. Defaults to the inherited TERM, or xterm-256color when TERM is unset or dumb.
```

### Options inherited from parent commands

```
      --debug   Enable debug logging (log file: /home/user/.local/state/upterm/upterm.log). A non-empty DEBUG turns it on too.
```

### SEE ALSO

* [upterm](upterm.md)	 - Instant Terminal Sharing

###### Auto generated by spf13/cobra on 18-Oct-2026
