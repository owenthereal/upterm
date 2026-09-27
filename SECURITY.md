# Security Policy

## Supported versions

Security fixes land on the latest minor release. Please upgrade before
reporting — the issue may already be fixed.

| Version | Supported |
| ------- | --------- |
| Latest minor | Yes |
| Anything older | No |

## Reporting a vulnerability

Report it privately through GitHub, not in a public issue:

1. Go to [Security → Report a vulnerability](https://github.com/owenthereal/upterm/security/advisories/new).
2. Describe what you found.

That opens a private advisory only you and the maintainers can see.

Useful things to include, as far as you have them:

- the upterm and uptermd versions (`upterm version`), and the relay you used;
- what an attacker gains, and what they need beforehand;
- the smallest reproduction you have.

## What to expect

- An acknowledgement within 7 days.
- An assessment, and a fix or an explanation of why it is not one, within 30
  days.
- Credit in the advisory, unless you would rather not be named.
- For anything affecting the public relay at `uptermd.upterm.dev`, the relay is
  patched before the advisory is published.

Please give us a chance to ship a fix before disclosing publicly.

## Scope

In scope: the `upterm` client, the `uptermd` relay, the Helm chart, and
[action-upterm](https://github.com/owenthereal/action-upterm).

Out of scope: that a relay operator can see traffic they are relaying, and that
a session's owner can run commands on their own machine. Both are what upterm
is for. A relay you do not control is a party you are trusting — see the host
key verification notes in the README.
