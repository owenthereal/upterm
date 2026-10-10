# Reach your Herdr agents from anywhere

Leave your agents running in [Herdr](https://github.com/herdrdev/herdr) on the
machine at home, and check on them, approve or steer them from a phone or
another laptop. upterm is the door: it gives the machine an address you can
reach from anywhere, without opening a port. Herdr keeps the agents, so losing
the door costs a rejoin, not the work.

This needs upterm v0.37.0 or later, and Herdr 0.9.0 or later (its saved
machines, and clients that view tabs independently).

## Open the door

On the machine running Herdr:

```console
upterm host --detach --name home --accept \
  --authorized-user github:YOUR_GITHUB_USER \
  --force-command 'env -u HERDR_ENV herdr'
```

- Each guest gets a Herdr client of its own, with a layout for its own
  screen: on a phone (64 columns or fewer), Herdr switches to its mobile
  layout. Clients looking at the same tab share its panes, though, and Herdr
  sizes them for the client that last interacted with the tab, so the agent
  repaints when you switch from the laptop to the phone.
- `--authorized-user` lets in only the keys on your GitHub account, as they
  are when the door starts: after you add, change or revoke a key on GitHub,
  restart the door. Without it, anyone with the session ID can join, and
  upterm warns you so.
- `env -u HERDR_ENV` matters when you start the door from inside a Herdr
  pane: Herdr refuses to start "nested" when it sees that variable. Outside
  Herdr, it does nothing.
- With no command after `--`, the session's own command is your shell. Nobody
  sees it, but it holds the door open: the door lasts as long as it does.
  Don't `upterm attach home` and type `exit`. Use `upterm session info home`
  to look, and `upterm session stop home` to close the door.
- Copy inside Herdr goes to the guest's clipboard, over OSC 52.
- When the door closes, or a guest's Herdr exits, upterm puts the guest's
  terminal back.

`upterm session info home` prints the connect command. The session ID in it
stays the same through network drops and relay deploys, for as long as the
door runs. It changes when you restart the door.

## Keep the Mac awake

On AC power, `caffeinate` stops the Mac idling to sleep for as long as the
door runs (it needs `jq`; `brew install jq` if `command -v jq` finds none):

```console
caffeinate -is -w "$(upterm session info home -o json | jq .pid)" &
```

It can't stop the sleep that closing the lid forces: leave a laptop's lid
open, or run it closed only in clamshell mode, with power and an external
display.

## Connect from a laptop

Pin the relay's host certificate once (see [Running Without a
Terminal](../README.md#running-without-a-terminal) for the fingerprint to
check):

```console
mkdir -p ~/.ssh
cat >> ~/.ssh/known_hosts <<'EOF'
@cert-authority uptermd.upterm.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4
EOF
```

Then give the door a name in `~/.ssh/config`, with the user from the connect
command `upterm session info home` prints (on the public relay, that's the
session ID):

```
Host home
  HostName uptermd.upterm.dev
  User SESSION_ID
```

`ssh home` lands you in Herdr.

## Connect from a phone

In Termius or Blink, add a host with:

- **Host:** `uptermd.upterm.dev`, port 22;
- **Username:** the user from the connect command (the session ID);
- **Key:** one whose public half is on your GitHub account.

Connecting lands you in Herdr's mobile layout.

## `herdr --remote`, VS Code and scp: jump to the machine's own sshd

`herdr --remote` and VS Code Remote-SSH need a real SSH server. If the
machine runs one (Remote Login on macOS, sshd on Linux), jump to it through
the door; scp then works through the same jump. The inner connection is end
to end between you and the machine's sshd; the relay forwards only
ciphertext.

Open the door with forwarding allowed, instead of the command above. If a
door named `home` is already running, stop it first with
`upterm session stop home`; the new door gets a new session ID, so update
your clients' `User`, and start `caffeinate` again for the new pid.

```console
upterm host --detach --name home --accept \
  --authorized-user github:YOUR_GITHUB_USER \
  --force-command 'env -u HERDR_ENV herdr' \
  --allow-local-tcp-forwarding
```

and add to `~/.ssh/config`:

```
Host home-sshd
  HostName localhost
  User YOUR_USER_ON_THE_MACHINE
  HostKeyAlias home-sshd
  ProxyJump home
```

`User` is your account on the machine at home, and the machine's sshd has to
accept your key for it (in that account's `~/.ssh/authorized_keys`).

Now `herdr --remote home-sshd`, `scp file home-sshd:`, and VS Code's
"Remote-SSH: Connect to Host… home-sshd" all work. `upterm session info home`
lists each jump as `jump … → localhost:22`.

Run `herdr --remote` from an ordinary terminal, not from inside a Herdr pane:
a pane's `HERDR_ENV` sets off Herdr's nested-client guard, and its
`HERDR_SESSION` can pick a remote session you didn't mean.

`--allow-local-tcp-forwarding` lets a guest reach anything the machine can
reach, your LAN included, so use it only with `--authorized-user`.

## Saved machines in Herdr

Herdr's saved machines connect with `BatchMode=yes` and
`StrictHostKeyChecking=yes`, so they never prompt, and an unknown host key
fails the connection without a word. Pin the relay as above first. Then
save `home-sshd` as the machine, and record the home machine's own host key
before Herdr uses it: connect once with `ssh home-sshd`, and check the
fingerprint it shows against `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
on that machine before you accept it.

## Share an agent through a door, not its own terminal

`upterm host -- claude` shares Claude Code's own terminal: every guest sees
one screen at the smallest guest's size, and a guest who joins at a different
size can find the earlier scrollback garbled. Through a Herdr (or tmux) door,
each guest gets a client of its own, and joining never replays the agent's
transcript. Clients looking at the same tab do share its size: Herdr sizes it
for the client that last interacted with the tab, so focusing a tab, selecting
it or a client leaving can resize the agent.

## Sensitive work

Traffic through the public relay is decrypted there, apart from the jump to
your own sshd. For sensitive work, [run your own
relay](../README.md#hammer_and_wrench-deployment): it's one binary.
