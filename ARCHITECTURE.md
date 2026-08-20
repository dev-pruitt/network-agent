# Architecture

A self-hosted monitoring and remediation agent for a dual-WAN OpenWrt router
running two outbound WireGuard tunnels, plus a Tailscale subnet router for
remote access.

Written for a specific home network, but the failure modes it documents are
general — most of this file is about *how monitoring lies*, which is not
site-specific.

## Shape

```
                 ┌──────────────┐        ┌──────────────┐
   WAN 1 ────────┤              ├── wg1 ─┤  VPN exit A  │
   (primary)     │   OpenWrt    │        └──────────────┘
                 │    router    │        ┌──────────────┐
   WAN 2 ────────┤              ├── wg2 ─┤  VPN exit B  │
   (secondary)   └──────┬───────┘        └──────────────┘
                        │ LAN
                 ┌──────┴───────┐
                 │  agent host  │  polls the router over SSH,
                 │   (Debian)   │  runs analysis + remediation,
                 └──────┬───────┘  serves the dashboard,
                        │          acts as Tailscale subnet router
                 ┌──────┴───────┐
                 │ phone / etc. │  reaches the LAN from anywhere
                 └──────────────┘
```

The agent pulls telemetry over an existing SSH channel rather than having the
router push. The router therefore needs no inbound ports, no credentials, and
no listener — the trust direction is always agent → router.

## Components

| Path | Role |
|---|---|
| `agent-pc/scripts/router_poll.py` | Telemetry: tunnel state, latency, transfer, uptime |
| `agent-pc/scripts/analyze_telemetry.py` | Local LLM analysis of the telemetry stream |
| `agent-pc/scripts/diagnose_issue.py` | Turns anomalies into diagnoses |
| `agent-pc/scripts/execute_action.py` | Executes Level 1 actions, escalates the rest |
| `agent-pc/scripts/execute_wireguard_rotation.py` | Autonomous tunnel rotation under guardrails |
| `agent-pc/scripts/drain_router_alerts.py` | Router alert spool → proposals (or notices) |
| `agent-pc/scripts/discord_relay.py` | Posts proposals, reads approve/deny reactions |
| `agent-pc/scripts/tailscale_watchdog.py` | Keeps remote access up, repairs what it can |
| `agent-pc/scripts/tailscale_poll.py` | Tailnet state via API: route approval, key expiry |
| `dashboard/` | Flask UI — status, tunnels, servers, proposals, actions, health |
| `router/remediation-*/` | Router-side fix scripts, each documenting the fault it repairs |

## Escalation model

```
Level 1   agent acts autonomously
Level 2   requires approval, except tunnel rotation (see below)
Level 3   manual or physical intervention
```

`config/guardrails.toml` (not published) defines forbidden actions, per-action
cooldowns, and which conditions map to which level. It is loaded fail-closed:
if it is missing or unparseable, the executor refuses to act.

### Autonomous tunnel rotation

One Level 2 action runs unattended. Three independent ceilings apply:

1. a per-action cooldown
2. a daily cap, after which it **falls back to approval rather than going dark**
3. the router's own per-tunnel rotation cooldown

Rotation itself measures before committing. Two modes:

- **recover** — tunnel is dead, any working peer is an improvement, first one wins
- **optimise** — tunnel is up but slow: probe several candidates, measure each,
  and commit only on a material gain, otherwise revert to the incumbent

That second mode exists because the original implementation accepted any
candidate that merely completed a handshake. Latency was never measured, so
rotation was a coin flip — and observed in practice, both tunnels ended up
slower than before they rotated, each downgrade raising the rolling baseline
that armed the next trigger.

## Remote access

A Tailscale subnet router on the agent host advertises the LAN and offers an
exit node. Chosen over a listening WireGuard server because neither WAN has a
public IP — one sits behind an ISP gateway, the other behind CGNAT. A
listening server would have required a port forward, dynamic DNS, and a policy
route to stop replies being swallowed by the outbound VPN.

`tailscale_watchdog.py` repairs what can be repaired locally (dead daemon,
dropped route advertisement, un-advertised exit node) and **only warns** about
what cannot (node key expiry, re-authentication) rather than looping on it.

---

# What this project is actually about

Every significant bug found in this system had the same shape: **a value that
had to track something, and didn't.** They are worth reading as a set, because
each one produced confident, specific, wrong output — which is worse than
silence, since it sends you chasing problems that don't exist.

### 1. Counting the wrong rows

A DNS-leak monitor summed *all* counters in an iptables chain and reported the
delta as "packets escaped the tunnel". The chain's first rows were `RETURN`
rules matching legitimate in-tunnel DNS. Healthy traffic was being reported as
a leak, continuously, for weeks.

The fix was reading rows 9–12 instead of 1–4. The rows had shifted when the
chain grew from 4 rules to 12; the shape gate was updated, the field offsets
were not.

**Lesson:** when a data structure grows, every positional read of it is now
wrong and nothing will tell you.

### 2. Config that doesn't follow a moving target

Four separate instances:

- a route pin naming a tunnel endpoint that rotation had since changed
- a firewall zone that existed for one tunnel and not its twin
- leak-detection exclusions rebuilt only at boot, so any rotation invalidated them
- a monitored device list hardcoded to addresses DHCP had long since reassigned

The last one is the starkest: the monitor watched two IPs, one belonging to an
unrelated device and one to nothing at all, and reported both as critical for
weeks while the real devices were online the entire time.

**Lesson:** anything that must follow a rotating or reassigned value needs to
be derived at use time, or verified as an invariant. Vendor OUI and DHCP
hostname beat a hardcoded address.

### 3. Asserting a condition from a signal that can't support it

A monitor declared devices "down" from mDNS silence in an 8-second capture —
no ping, no ARP check, and a window far shorter than the announcement
interval. The devices turned out to be cloud-connected units that never
advertise over mDNS at all. The check could only ever have been a permanent
false alarm.

Its replacement was *also* wrong at first: it inferred "not controllable" from
a missing conntrack entry, when an idle long-lived session simply ages out.

**Lesson:** ask what the signal can actually prove. If the answer is "not
much", record it as an observation, not a verdict.

### 4. Failure to observe reported as failure

Probe errors — "could not read counters", an SSH timeout captured as a WAN IP
change — were filed as conditions requiring human decisions. They are not
conditions. They mean the agent failed to look.

**Lesson:** distinguish *cannot observe* from *observed a fault*. Log both,
alert on one.

### 5. Notifications shaped like questions

Every router alert became a proposal with status `pending`, including routine
success notices. They accumulated until genuine security items were buried
among them — and the source already distinguished the two cases, in a field
nobody read.

**Lesson:** news and questions need different queues.

### 6. Loopback treated as egress

A DNS-leak chain allowed RFC1918 destinations but not `127.0.0.0/8`, so the
router's own queries to its local resolver were dropped. The router had no
working name resolution for an extended period. LAN clients were unaffected
because they used the LAN address, which is why nobody noticed — and the
dropped queries inflated the very counter meant to detect real leaks.

**Lesson:** a check that fails only for one class of caller will hide for a
long time.

### 7. Half a change: a zone with no forwarding rule

The best example in the set, because it hid for the entire life of the
project and was found by accident.

A second tunnel was added for load balancing. A firewall *zone* was created
for it, mirroring the first tunnel's — masquerade, MTU clamp, the lot. The
zone *forwarding rules* that make a zone reachable were not. So the mangle
table faithfully assigned 30% of new connections to the second tunnel, and
the firewall rejected every one of them under its default forward policy.

Measured from the LAN, with two destinations statically pinned one per
tunnel:

```
-> pinned to tunnel 1   11/15 ok
-> pinned to tunnel 2    0/15 ok    FORWARD-reject counter +15
```

Three things made it survive so long:

- **Every check reported healthy.** The tunnel handshook, the interface was
  up, the zone existed. Nothing inspected whether a packet could actually
  cross from the LAN into it.
- **The failure looked like someone else's problem.** 30% of new connections
  failing presents as "the internet is flaky" — retries work, so it gets
  absorbed as noise rather than reported as a fault.
- **The byte counters looked like disuse, not blockage.** The second tunnel
  carried 261 KB against the first tunnel's 3.7 GB. That reads as an idle
  standby. It was a blocked one. After the fix it moved three times its
  lifetime total in thirty seconds.

**Lesson:** adding a capability is usually more than one edit, and the piece
you forget is the one nothing tests. If a config object exists in order to be
*used*, the health check has to exercise the use, not confirm the existence.
Handshakes and interface state are not reachability.

### 8. Half-present IPv6

An interface carried a global IPv6 address while no IPv6 default route
existed. The OS therefore advertised v6 capability it could not honour, and
any client using happy-eyeballs with a fixed deadline would stall on it.
`curl` survived by falling back quickly; a Go HTTP client did not.

**Lesson:** a half-configured address family is worse than none.

## Design rules that came out of this

- **Corroborate before asserting.** A single signal that *could* mean a fault
  usually needs a second one that agrees.
- **A probe failure is not a condition.**
- **Verify every repair.** No fix reports success without re-reading state.
- **Cooldown everything**, so a persistent fault produces a steady note
  rather than a loop.
- **State scope honestly.** A check that verifies configuration should not
  claim to verify reachability.
- **Exercise the path, don't inspect the config.** A zone, a route or a peer
  existing says nothing about whether traffic crosses it. Send a packet.
- **Low, non-zero throughput is a symptom.** A link carrying a trickle is
  more suspicious than one carrying nothing — it means something works and
  something else does not, which is harder to notice than an outright dead
  link and usually means a partial configuration.
- **Watch the watcher.** Monitoring credentials and node keys expire; when
  they do, the monitor goes quiet and nothing explains the silence.
- **Derive, don't hardcode**, anything that can move.

## Publication

The public repository is built by `publish-public.sh` as a filtered artefact,
not a branch: an allowlist, a fail-closed secret scan, and a single orphan
commit so no prior history is carried across. Operational logs, configuration,
VPN server pools and router configuration snapshots are excluded and are not
recoverable from this history.
