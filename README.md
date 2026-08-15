# Makozumi 真

**Truly Genuine** — a universal authenticity check for physical items. Tap an
NFC tag, and a signed record of what the item is, who issued it, and when
appears instantly, verified by public-key cryptography. No server, no
database, no accounts.

Live at **https://katsuma0.github.io/makozumi/**

## How it works in one paragraph

Each item carries a code containing its details plus an **ECDSA P-256**
signature made with a private key that only the issuer holds. The code is
written to an NFC chip as a URL. Tapping the chip opens the verifier, which
checks the signature against the public key published in this site — with no
button presses — and shows ✓ AUTHENTIC or ✕ NOT AUTHENTIC. Anyone can verify;
only the private-key holder can issue. That asymmetry rests on the elliptic
curve discrete logarithm problem.

## Pages

| Page | What it does |
|---|---|
| `index.html` | The verifier. Auto-checks a code from the tapped URL, a paste, or a Web NFC scan. |
| `generate.html` | Private issuing tool. Signs new items locally; blocked from all network access so the key cannot leave your device. |
| `security.html` | Full threat model — every attack considered, what stops it, and the one that nothing stops. |
| `how-it-works.html` | The mathematics: curves, ECDLP, the sign and verify equations. |
| `revoked.json` | Published revocation list, checked on every verification. |
| `tests/attack-suite.mjs` | 60 automated attacks run against the real pages in a real browser. |

## Issuing a new item

1. Open `generate.html` (locally is fine — it works offline from disk).
2. Paste your private key JWK, fill in the item details, press **Sign**.
3. Open the generated link in a browser and confirm it reads ✓ AUTHENTIC.
4. In **NFC Tools**: Write → Add a record → **URL** → paste → Write.
5. **Lock the tag.** An unlocked chip can be rewritten by anyone who can touch
   your product — this is the easiest real-world attack on the system.

Use **NTAG215** or **NTAG216** chips. A typical code URL is ~250–300 bytes;
NTAG213 (144 bytes) is too small. The issuing tool reports which chips fit.

## Code format

```
https://katsuma0.github.io/makozumi/#<base64url(payload)>.<base64url(signature)>
```

The payload is compact JSON. Only `p` (item), `sn` (serial), and `o` (issuer)
are required; everything else is optional, which is what makes the format
usable for products, certificates, tickets, or documents alike.

| Field | Meaning |
|---|---|
| `v` | Format version |
| `kid` | Which issuing key signed this (enables key rotation) |
| `sn` | Serial number — unique per item, never reused |
| `p` | Item name |
| `t` | Type or category |
| `o` | Issued by |
| `d` | Issue date |
| `exp` | Valid until — after this, the verifier reports EXPIRED |
| `b` | Batch or edition |
| `n` | Free-text note |

The signature is 64 bytes (r‖s, IEEE P1363) over the base64url payload string,
hashed with SHA-256. The code rides in the URL **fragment**, so it is never
sent to any server — verification is entirely client-side.

## Security summary

Read `security.html` for the full account. In short:

**Stopped:** inventing codes · editing a signed code · signing with another key ·
algorithm-confusion tricks · reusing a signature on different data · scripts or
hidden text inside a payload · oversized or malformed input · framing the
verifier inside a fake page · third-party code (there is none) · using a code
after the item is reported lost (revocation) · indefinite use of a stolen key
(key rotation).

**Not stopped — and unstoppable by cryptography alone:** copying a genuine code
onto a second chip. The copy is not a forgery; it is the original. Unique
serials make duplicates detectable, revocation kills a copied serial, and
NTAG 424 DNA chips (which compute a fresh code on every tap) are the real fix
when the value justifies the cost.

### Key management

- The **public key** is in `assets/makozumi.js`. It can only verify.
- The **private key is not in this repository** and must never be committed.
  Store it in a password manager and back it up — losing it means no new codes
  can ever be issued under that key.
- If a key is exposed: mark it `retired` in `assets/makozumi.js`, publish a new
  key under a new `kid`, and add the affected serials to `revoked.json`.

### Revoking an item

Add its serial to the `revoked` array in `revoked.json` and push. The verifier
fetches this file on every check and reports **REVOKED** for a listed serial
even though its signature is still valid.

## Running the tests

```bash
npm install playwright-core
node tests/attack-suite.mjs
```

Without an issuing key the suite runs its negative and page-defence checks and
skips the rest. For the full run, supply the key out of band:

```bash
MAKOZUMI_PRIVATE_JWK='{"kty":"EC",...}' node tests/attack-suite.mjs
# or place it in .secrets/issuer.jwk (git-ignored)
```

## Deployment

Pushing to `main` deploys to GitHub Pages via `.github/workflows/pages.yml`.
The site is entirely static and loads no external scripts, fonts, or trackers.
