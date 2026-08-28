# Security policy

## Supported release

Version 0.7.x is an alpha implementation. Security fixes may change policy
behavior; pin exact versions and rerun your own regression set before updating.

## Reporting a vulnerability

Do not include credentials, private prompts, customer data, or live exploit
payloads in a public issue. Use GitHub's private vulnerability reporting for
this repository when available. If that channel is unavailable, open a public
issue containing only a request for a private contact channel.

## Scope boundary

This component does not claim complete prompt-injection prevention. It assumes
the caller still enforces least privilege, explicit approval for consequential
actions, sandboxing, audit logs, and rollback. Scanner admission is never
authorization for a tool action.

