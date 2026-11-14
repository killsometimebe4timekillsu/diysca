# Alerts

diysca tells you about new vulnerable packages through **channels** (where a message goes) and
**subscriptions** (which findings go to which channel). Channels use [Apprise](https://github.com/caronc/apprise/wiki),
so one URL format covers ntfy, Gotify, e-mail, Matrix, Slack, Teams, Telegram, Discord, generic webhooks and about
100 more services.

* [How it works](#how-it-works)
* [Channels](#channels)
* [Subscriptions](#subscriptions)
* [What a message looks like](#what-a-message-looks-like)
* [Mitigation updates](#mitigation-updates)
* [Recipes](#recipes)
* [Testing and troubleshooting](#testing-and-troubleshooting)

## How it works

1. A scan finishes (scheduled, `diysca scan`, the **Scan** button or `POST /api/scan`).
2. Every **open** finding (not ignored, not resolved) is checked against every enabled subscription.
3. Matching findings are grouped **per system and per channel** into one message, worst first
   (known exploited, then severity, then CVSS). One message holds at most 25 findings; the rest are counted.
4. Each finding is sent to a channel **once**. Failed deliveries are retried on the next run.
5. Every delivery is logged: *Settings > Notifications > Recently sent* and the *Notifications* panel of each finding.

Alerts are also sent by `diysca notify` (add `--dry-run` to print instead of send) and by the
*Send pending alerts now* button.

## Channels

*Settings > Notifications > Channels*, `diysca channel NAME URL`, or the `channels:` part of a settings import.

| Service | Apprise URL |
|---|---|
| ntfy (self-hosted, HTTPS, with login) | `ntfys://user:pass@ntfy.example.org/cve` |
| ntfy.sh | `ntfy://ntfy.sh/my-secret-topic` |
| Gotify | `gotifys://gotify.example.org/APP_TOKEN` |
| E-mail (SMTP with STARTTLS) | `mailtos://user:pass@smtp.example.org?to=sec@example.org&from=diysca@example.org` |
| Matrix | `matrixs://user:pass@matrix.example.org/#security:example.org` |
| Slack (incoming webhook) | `slack://T000/B000/XXXX` |
| Microsoft Teams (workflow webhook) | `workflows://…` (see the Apprise wiki) |
| Telegram | `tgram://BOT_TOKEN/CHAT_ID` |
| Discord | `discord://WEBHOOK_ID/WEBHOOK_TOKEN` |
| Any HTTP endpoint, JSON body | `jsons://hooks.example.org/diysca` |

Use the **Test** button next to a channel to send a test message. Channel URLs contain secrets: they are masked
in the UI and in exports (`***`), and importing `***` keeps the stored URL.

High and critical alerts are sent with Apprise's *failure* type (red / high priority on ntfy and Gotify), everything
else as *warning*.

## Subscriptions

A subscription says: *findings on these systems, in these packages, at least this severe, go to this channel*.

| Field | Meaning | Examples |
|---|---|---|
| Systems | Glob patterns on system name or address, comma separated. `group:` matches Ansible inventory groups, `!` excludes. Containers are named `host/container`. | `*` · `web*,db1` · `group:prod,!group:lab` · `*/nginx*` |
| Packages | Glob patterns on the source package **and** every binary package built from it, so `openssl` also matches `libssl3`. `!` excludes. | `*` · `postgresql*,libpq*` · `!linux-image*` |
| Min severity | `CRITICAL`, `HIGH`, `MEDIUM` or `LOW`. Findings without a severity (no CVSS anywhere) are not sent; check them on the Findings page. | `HIGH` |
| Only known exploited | Only findings listed in CISA KEV. | |
| Only if fix is in my repos | Only findings you can patch right now (the fixed version is in the system's repos). | |

A finding that matches several subscriptions of the same channel is sent once. If no subscription is enabled,
nothing is sent.

CLI: `diysca subscribe "postgres prod" --channel ntfy --hosts 'group:prod' --packages 'postgresql*,libpq*' --min-severity HIGH`

## What a message looks like

Title: `[diysca] CRITICAL CVE-2025-1094 in postgresql-16 on db1` for one finding,
`[diysca] 4 new vulnerabilities on db1 (worst: CRITICAL)` for several.

```
CRITICAL  CVE-2025-1094  postgresql-16 16.6-1~deb12u1  (CVSS 9.8, EPSS 61%, KNOWN EXPLOITED)
  PostgreSQL quoting APIs miss neutralizing quoting syntax in text that fails encoding validation
  -> 16.7-0+deb12u1 is in your repos: patch it, or approve it for mitigation
  https://diysca.example.org/findings/812
HIGH  CVE-2025-24928  libxml2 2.9.14+dfsg-1.3~deb12u1  (CVSS 7.8)
  -> the fix (2.9.14+dfsg-1.3~deb12u2) isn't in your repos yet: update the repo mirror (Patching > Patch), then patch
  https://diysca.example.org/findings/815

All open findings on db1: https://diysca.example.org/findings?host=db1
Approve for mitigation: https://diysca.example.org/findings?host=db1&approval=unapproved (select, then Approve for mitigation)
```

The `->` line says what to do:

| Situation | Hint |
|---|---|
| Fixed version is in the system's repos | patch it, or approve it for mitigation |
| Fix released, but your repos don't have it yet | update the repo mirror (aptly / Pulp / Foreman, *Patching > Patch*), then patch |
| Language package (PyPI, npm, …) | bump the dependency in the application, with the lockfile or directory |
| No fix released | check the advisory for workarounds, or ignore it if it doesn't apply |

EPSS is shown from 1% up and only when an `epss` source is configured. Set `base_url` in config.yml so the links
point to your diysca.

## Mitigation updates

When findings that were alerted are approved for [mitigation](mitigations.md), the same channels get a short
message when the mitigation is claimed, done or failed: `[diysca] Mitigation #12 done` with the systems, who
approved it and a link.

## Recipes

**Only what I can patch today, prod only, to the on-call ntfy topic**
Systems `group:prod`, packages `*`, min severity `HIGH`, *only if fix is in my repos*.

**Everything known exploited, everywhere, by e-mail**
Systems `*`, packages `*`, min severity `LOW`, *only known exploited*.

**One team's packages**
Systems `group:db`, packages `postgresql*,libpq*,pgbouncer`, min severity `MEDIUM`, channel `matrix-dba`.

**Containers separately**
Systems `*/*` (containers only) to one channel, and `*,!*/*` (hosts only) to another.

## Testing and troubleshooting

* **Test button** on a channel: sends "[diysca] test" right away and shows the error if Apprise refuses the URL.
* `diysca notify --dry-run` prints every message that *would* be sent, with its channel, without marking anything sent.
* Nothing arrives? Check that a subscription is enabled, the channel is enabled, and the findings are open and
  not sent before (*Recently sent*). Delivery errors are also listed under *Recent events* on the dashboard.
* Behind an egress proxy, set `HTTPS_PROXY` for the diysca process; Apprise uses it.
* Too many messages on the first scan? A new subscription also covers findings that already exist, so the next
  run sends them all (batched per system). Start narrow (*only known exploited* or *only if fix is in my repos*)
  and widen it later.
