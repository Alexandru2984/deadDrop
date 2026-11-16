# Reporting a vulnerability

Write to **984.alexmihai@proton.me**. Please do not open a public issue for
something that could be used against a person using Dead Drop before it is
fixed.

A report is most useful with:

- what an attacker needs (a page the victim visits, an account, a place on the
  network, the server itself);
- what they get (a message, an address, an identity, a way to stop someone
  from using the service);
- the steps, or a script, that show it;
- the version: `deaddrop version`, or the digest at the bottom of
  `/verify.html`.

## What counts

Anything that breaks a promise the [README](README.md) or the
[privacy review](PRIVACY_REVIEW.md) makes: reading or altering a message, file
or call; learning who somebody talks to beyond what those documents already
say the server and the relay can see; getting past the safety code; taking
over, locking or enumerating accounts; keeping data that Panic, a timer or a
sign-out should have removed; serving code the verifier does not catch.

The known limits are written down in the same two documents — the proxy in
front of the public site terminates TLS, a compromised device reads
everything, and nobody independent has audited the protocol yet. Those are
not news, but a way to make one of them worse than described is.

## What happens next

You get an answer saying whether it reproduces. Fixes ship as a release marked
**Security** in the [changelog](CHANGELOG.md), with the test that would have
caught it; you are credited there unless you would rather not be. There is no
bounty.

## A deployment that is not this one

Dead Drop can be run by anyone. If the service you are looking at is not
`dead.micutu.com`, its operator's contact is at `/.well-known/security.txt` on
that host, when they have published one. A flaw in the code itself still
belongs here.
