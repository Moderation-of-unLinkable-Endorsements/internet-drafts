<!-- regenerate: off (set to off if you edit this file) -->

# MoLE IETF drafts

This is the working area for MoLE IETF drafts. The current items are as follow

1. [Architecture](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-architecture.html) (Datatracker - not published yet)
2. [HTTP Transport](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-http-transport.html) (Datatracker - not published yet)
3. [Cryptography integration](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-protocols.html) (Datatracker - not published yet)

You can find all drafts and diff on [GitHub Pages](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/).

The associated mailing list is [mole@ietf.org](https://mailarchive.ietf.org/arch/browse/mole/) ([Subscribe](https://mailman3.ietf.org/mailman3/lists/mole.ietf.org/)).

## Architecture overview

The architecture has three parties:

- **Client**: holds credentials and produces presentations.
- **Anchor**: issues a publicly verifiable credential attesting to some scarce signal.
- **Moderator**: holds policy, accepts anchor credentials from a configured set, and issues per-Moderator credentials that gate updates and queries against a site.

### Privacy properties

- Moderator credentials must be **information-theoretically unlinkable**: no party can link two presentations of the same credential chain to each other or to issuance.
- Anchor credentials must be **computationally unlinkable**, including against quantum-capable adversaries.
- A presentation against a Moderator's accepted set `A` must be **issuer-hiding**, revealing only that the underlying anchor credential came from some Anchor in `A` and not which one.

### 1. Anchor Issuance

The client obtains a publicly verifiable anchor credential from an Anchor.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant An as Anchor

    Note over C: ctx := newCtx()
    Note over C: req := makeReq(ctx, pk_An)

    C->>An: req, blob

    Note over An: authorize(blob)
    Note over An: (resp, status) := issueAnchor(req, sk_An)

    An->>C: resp, status

    Note over C: anc_cred := finalizeAnchor(ctx, req, resp, anchor_id)
```

### 2. Transfer (Anchor to Moderator)

The client converts an anchor credential into a moderator credential bound to a specific Moderator's policy.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant Mod as Moderator

    Mod->>C: A, pk_Mod, pol

    Note over C: ctx := newCtx()
    Note over C: req := makeReq(ctx, pk_Mod, pol)
    Note over C: pres := presentAnchor(anc_cred, A)

    C->>Mod: req, pres

    Note over Mod: verifyAnchor(pres, A) ok
    Note over Mod: cs := initialState()
    Note over Mod: resp := issueMod(req, sk_Mod, cs)

    Mod->>C: resp, cs

    Note over C: mod_cred := finalizeMod(ctx, pk_Mod, pol, req, resp, cs)
    Note over C: store(mod_cred, pk_Mod, pol, A)
```

### 3. Update / Query

The client makes a request against a site, which mediates through a specific Moderator. The Moderator verifies the presentation, updates state, and returns a fresh credential and a status.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Site
    participant Mod as Moderator

    S->>C: Moderator identity (pk_Mod, pol)

    Note over C,Mod: if no mod_cred for this Moderator, run Transfer first

    Note over C: ctx := newCtx()
    Note over C: req := makeReq(ctx, pk_Mod, pol)
    Note over C: pres := presentMod(mod_cred, pk_Mod, pol)

    C->>S: blob, req, pres

    Note over S: site may withhold parts of blob from Moderator
    S->>Mod: req, pres, stuff

    Note over Mod: verifyMod(pres, pol, sk_Mod) ok
    Note over Mod: d := update(stuff)
    Note over Mod: (resp?, status) := respondMod(req, sk_Mod, d)

    Mod->>S: resp?, status

    Note over S: blob2 := integrate(blob, status)

    S->>C: resp?, blob2

    Note over C: mod_cred := finalizeMod(ctx, pk_Mod, pol, req, resp)
```

## Contributing

See the
[guidelines for contributions](https://github.com/Moderation-of-unLinkable-Endorsements/internet-drafts/blob/main/CONTRIBUTING.md).

The contributing file also has tips on how to make contributions, if you
don't already know how to do that.

## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).
