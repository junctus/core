# neo — monetization & economic sustainability

How value can flow through neo without breaking the properties neo exists to provide.
This is **design, not shipped code** — the money-touching parts sit on the far side of
the [Audit gate](MILESTONES.md), and several depend on primitives that are not built yet.
Read it as a set of invariants and a sequenced plan, not a launched product.

Nothing here uses a blockchain, a coin, or KYC.

---

## Why this is hard for neo specifically

Every ordinary way a VPN makes money is a way neo would betray itself:

- **Accounts + metered billing** re-attach an identity to usage — the exact linkage
  Sphinx onion routing (M2) and PIR-degenerate witnessed snapshots (M4.5) were built to destroy.
- **Card / bank / app-store payment** is a censorship *and* deanonymization chokepoint: card
  networks decline circumvention merchants, exchanges KYC and geo-block, and Apple/Google have
  delisted VPN apps on state request. A censor can kill a paid neo by leaning on **one** payment
  processor — far cheaper than blocking the DoH bootstrap + snapshot + bridge machinery
  (M18/M29/M35) neo built to be un-blockable.
- **Charging users** excludes exactly the people neo is for: someone behind the GFW often has no
  working card, and *paying for circumvention is itself dangerous*.

So the question isn't "how do we bill for a VPN." It's: **how do money and bandwidth change hands
so operators are compensated and the project is sustainable, while payment can never be tied to
usage, and while the people who most need neo can always use it for free.**

## The invariants (non-negotiable)

These come first because the skeptic's analysis is unambiguous: without them as *hard design
rules*, monetization eats the mission. Every mechanism below is constrained by them.

1. **Money stays at the edges, never in the loop.** A credit is a closed-loop, usage-blind
   utility. Value may attach only at *identified* endpoints (funding in, operator payout out) —
   never to a circuit, a serial, or a spend.
2. **Earn-by-relaying is a *complete* path to credits.** A user's device/region may never be
   *required* to pay. If earning is impossible for a user (mobile, NAT'd, GFW-trapped), a free,
   donated allowance must reach them. Sending must never become a paywall on the core safety
   function.
3. **neo holds no float and custodies no value.** A pooled treasury / redemption escrow is a new
   trust root that can be subpoenaed, frozen (OFAC can list a wallet), hacked, and used to exclude
   operators — the opposite of the federated k-of-n witness model (DISCOVERY.md).
4. **No in-app purchase surface.** The app is fully functional with zero store transaction, so a
   store delisting degrades *reach*, never *function* — and there is no 30% tax or IAP identity
   to weaponize.
5. **No cash value attaches to a credit until proof-of-relay is un-forgeable.** Today's
   `RelayReceipt`s are client-attested and forgeable (`neo-credits::earn`, M17/M32); paying money
   for that signal is a direct fraud subsidy. See [the two-tier ledger](#the-two-tier-ledger).

## The one primitive that makes any of this possible

neo already ships the hard half of an anonymous mint. **`neo-credits`** (M10) is a Privacy-Pass
**VOPRF**: a node blinds a random serial, the issuer blind-evaluates it under one committed key
with a **DLEQ proof**, and the finalized credit later redeems against a double-spend set. Because
the issuer only ever saw a *blinded* serial, **issuance ↔ spend is cryptographically unlinkable**,
and the DLEQ forces one published key for everyone so a spend can't be key-tag-partitioned back to
its earner (`lib.rs`). M17 already gates issuance on a *pluggable* hook (`EarnLedger::redeem_earned`
in `earn.rs`).

That gives the organizing idea:

> **Identified edges, blind middle.** Value enters at an *identified-but-usage-blind* issuance,
> is spent *unlinkably* on bandwidth, and (only if ever) exits at an *identified-but-usage-blind*
> operator redemption. Money and traffic are severed by a blind signature, not by a promise.

Monetization is therefore **not a new crypto system** — it is mostly *new gates on the existing
`issue()`* plus honest plumbing. Four interchangeable ways to acquire the *same fungible token* —
relayed bandwidth, a payment, a donation, a sponsorship — all mint under the one shared key, so no
on-ramp becomes a distinguishable tier that re-partitions the anonymity set.

---

## The value flows

### Layer 0 — the money-free core (this is the default, and it must always suffice)

- **Earn ↔ spend (M32 relaykit).** Earn credits by relaying (proof-of-relay `RelayReceipt`), spend
  them to send. A closed barter loop: contribution funds your own anonymity. No money, no wallet,
  no KYC. This is the anti-free-rider / anti-Sybil mechanism, and per M32 it must be framed as
  **utility, not a payout**.
- **Donated free allowance for the censored.** Users who *can't* earn (locked-down devices, no
  reachable relay role yet — NAT traversal is still deferred) receive donated credits out-of-band
  via the voucher mesh below. This is how invariant #2 is honored in practice.

### Layer 1 — money **in** (safe-ish on today's crypto; the on-ramp is the caveat)

- **Paid blind-issuance** — a *second* gate beside the earn gate. The mint verifies a `PaymentProof`
  (a Monero txid + view-key-provable amount, a settled Lightning preimage, or a redeemed voucher)
  and blind-signs N credits, **fungible with earned ones** (same key, same spent set). Money enters;
  usage stays blind. *Default rail: Monero + vouchers* (no card, no bank, payable from a censored
  jurisdiction). Lightning is convenience-only — its channel graph and amount-correlation make it
  the weakest rail.
- **Prepaid vouchers / cash codes** — the strongest censorship-hard rail. A voucher is a one-time
  bearer secret redeemed for blinded credits; batches are sold for cash by resellers / mailed cards
  / in-person, *decoupling* the money-in event from the redeemer. A censored user receives a code
  over any channel (Signal, a printed card, a friend) and redeems it with **zero payment identity**.
  This is also the delivery path for donated free credits (Layer 0). Distribution can reuse M35's
  credit/PoW gating to resist enumeration/hoarding.
- **Mullvad-style anonymous account** — a random *account number* (no email, no name, no PII) that a
  buyer tops up (voucher/Monero) for a recurring credit **allowance**. It gates *how many* credits
  you may mint per epoch, never *which circuit* you build. Compatible precisely because onion
  routing already blinds the network to traffic and the VOPRF already blinds issuance to spend.
- **Committee-Exit-as-a-Service (CEaaS)** — B2B, mission-aligned. A newsroom / NGO pays to *provision*
  M28 committee-exit capacity for its sources and receives a bulk pool of unlinkable credits to
  distribute. By M28's `NonCustodyProof` DLEQ the sponsor is *structurally incapable* of
  deanonymizing its own sources — "even the exit can't rat you out, and here's the proof." (Honest
  limit: M28 is decrypt-direction only; the egress member still sees plaintext at send until M33.)
- **Public-goods / grants for the free tier + core development.** Grant/donor money buys the *same*
  fungible credits distributed free to censored users — it touches the **funding** ledger (who paid,
  off-path), never the blinded **spend** ledger. Honest caveat: the natural funders for a
  circumvention tool (OTF-adjacent, internet-freedom lineage) carry geopolitical baggage — "US-funded"
  is itself a threat label in some target regions — so grants must be *diversified and disclosed,
  never load-bearing alone*.

### Layer 2 — money **out** (the dangerous rail; heavily gated)

Operator compensation is where a barter coupon becomes a payout — and where the skeptic is loudest.
Two things must both be true before any credit converts to money:

- **The two-tier ledger.** <a id="the-two-tier-ledger"></a>
  - *Tier 1 — utility credits* (today): receipt-minted, spendable **only to send your own traffic**.
    Forging them just lets you free-ride — self-limiting, exactly M32's framing.
  - *Tier 2 — payout / bond value*: gated by signals a relay **cannot forge** — seed-measured
    continuous **uptime** (M36's unforgeable maturation gate), **bilateral co-signed** receipts
    (both hops attest at teardown), per-identity **rate/reputation caps** at the already-identified
    `issue()` boundary, and optional slashable **staking**. This rewards *availability +
    corroboration*, honestly **not** proof-of-bandwidth (which remains unsolved).
- **neo provides no payout rail.** Converting Tier-2 credits to fiat is money transmission, taxable
  income, and OFAC-screenable — a KYC/custody chokepoint that re-adds the liability M28 removed.
  So any cash-out is an **operator-self-directed, off-platform** act neo neither intermediates nor
  records; the docs must tell operators cashing out is *their* regulated act.

Everything in Layer 2 stays behind the Audit gate and behind the unbuilt prerequisites in
invariant #5.

---

## Incentive & pricing design

- **Price by role *risk*, not just bytes.** The `EarnLedger` can apply a per-role earn *multiplier*
  (exit-served bytes earn more than relay bytes; committee/bridge have their own rates) — all on the
  identified earn side, invisible at spend. Seeds/witnesses are paid out-of-band (governance), never
  by credits they could inflate.
- **M28 re-prices exits by *cutting liability*, not paying a premium.** Rather than a large solo-exit
  premium, split the exit reward across k low-liability committee members whose market-clearing rate
  is far lower — the cheapest supply unlock, needing no new crypto. (The single clearnet-egress member
  still sees plaintext at send, so that one role keeps a real premium until M33.)
- **Optional staking/bonding** on top of M36's caps + PoW: post a bond (as spent credits or an
  external deposit) bound to a relay's public `NodeId`; slash on *unforgeable, reproducible* evidence
  (failed dial-back, exit-policy/SSRF violation, inconsistent DKG accept-set), adjudicated k-of-n.
  Bonds must stay tiered/optional so a capital requirement never excludes poor honest operators.
- **Reject paid QoS / priority tiers.** Selling "speed" would partition users into premium vs free
  sets distinguishable by timing/shape — a fingerprint and a smaller (most-sensitive) anonymity set.
  Keep one uniform service class; if congestion pricing is ever needed, spend a token for admission
  in a way indistinguishable on the wire, never a per-circuit "premium" flag.

## Honest boundaries

Stated bluntly, because pretending otherwise is the failure mode:

- **A bought-and-redeemed credit is plausibly money transmission / stored-value / e-money, and maybe
  an unregistered security.** Unlinkability makes the AML posture *worse* (an anonymous value-transfer
  rail), not better. There is no "but it's for privacy" safe harbor. This is *the* gating constraint
  on Layer 2.
- **A paid on-ramp is a KYC'd, timestamped, censorable event upstream of the anonymity set** — it can
  deanonymize the *buyer* (a "this person funded neo" membership leak, distinct from usage) and
  exclude the censored. Cash-by-mail, Monero, and vouchers are primary *because* of this; no card rail
  is ever required.
- **Float/custody is a honeypot and a new trust root** — subpoenable, freezable, seizable, and able to
  exclude operators. Hence invariant #3.
- **App stores are the censor's lever** (delisting on state request) plus a 30% tax and an identity
  linkage — hence invariant #4.
- **Cash value amplifies the M17 forgeable-receipt problem into a profit motive.** M36 *deliberately
  declined* to weight path selection by these receipts because they're forgeable; monetization must
  not make that same forgeable signal financially load-bearing. Bilateral co-signed receipts +
  per-identity rate caps are hard prerequisites and **are not built**.
- **Operator cash-out is a taxable, sanctions-screened event** that pushes toward operator KYC —
  poisoning the low-liability altruism M28 was built to enable, worst at the highest-value roles.
- **Mission drift is the strongest failure mode:** metering usage and billing the users who can't
  relay. Metered/account billing is on the forbidden list. Invariants #1 and #2 exist to prevent it.
- **Nothing here is deployed or audited.** Adding a monetary layer *before* the audit compounds every
  risk above with real money and real users.

## Sequencing & a diversified funding stack

Sequence by **cryptographic readiness, not by revenue** — money-in is safe on today's crypto, money-out
is not:

1. **Persist the double-spend + a new unspent-payment/voucher set** before taking a cent (the M25/M32
   durability item). A mint restart that loses the set is a theft/inflation event.
2. **Paid blind-issuance + vouchers** (Layer 1) — one new gate beside `issue()`, reusing M10 verbatim;
   Monero + vouchers default. Least-entangled revenue, immediate cross-subsidy for the free tier.
3. **CEaaS** once M28 committees are Sybil-hardened — high-value, mission-aligned B2B.
4. **Only then, if ever, Layer 2** — behind bilateral receipts, rate caps, the regulatory analysis, and
   the audit gate.

No single source should be load-bearing: **paid users + B2B/CEaaS + diversified grants + individual
Monero donations**, so pressure on any one (a processor, a funder, a jurisdiction) can't stop the
network.

## Milestone map

| Piece | Status | Where |
|---|---|---|
| Unlinkable credit (VOPRF, DLEQ, double-spend) | ✅ M10 | `neo-credits::lib.rs` |
| Proof-of-relay receipts + `EarnLedger` | ✅ M17 (forgeable — see #5) | `neo-credits::earn` |
| Earn↔spend loop wired into the runtime | ⬜ M32 | relaykit |
| Seed-measured uptime (unforgeable Tier-2 signal) | ✅ M36 | `neo-seed` maturation gate |
| Committee no-wiretap exit (CEaaS product) | ✅ M28 (decrypt-direction) | `neo-node::committee` |
| Credit/PoW-gated distribution (vouchers/bridges) | ⬜ M35 | — |
| Paid issuance gate, vouchers, mints, persistence | ⬜ (this doc) | future |
| Bilateral co-signed receipts, staking, payout | ⬜ (behind audit gate) | future |

See also: `DISCOVERY.md` (federated witnesses, the trust model this mirrors), `MILESTONES.md`
(M10/M17/M28/M32/M35/M36 and the Audit gate).
