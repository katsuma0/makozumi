# Makozumi 真

Cryptographic product authentication with NFC tags — a fully static site that
verifies ECDSA-signed tags, deployable on GitHub Pages.

Every Makozumi product carries an NFC tag holding a URL. Tapping the tag opens
the verifier, which checks the tag's **ECDSA P-256 digital signature** against
the public key embedded in the site. Only the holder of the private key (you)
can create valid tags; anyone can verify them.

## Pages

| Page | Purpose |
|---|---|
| `index.html` | Verifier — opens when a tag is tapped, shows ✓ AUTHENTIC + product info, or ✕ NOT AUTHENTIC. Includes a Web NFC scan button (Android Chrome). |
| `generate.html` | Private minting tool — paste your private key (kept **offline**, never in this repo), fill in product details, get a signed tag URL. Signing runs entirely in your browser. |
| `how-it-works.html` | Course-style explanation of the ECDSA math (elliptic curves, ECDLP, sign/verify equations). |

## Setup: enable GitHub Pages

1. On GitHub: **Settings → Pages → Source: Deploy from a branch → `main` / root**.
2. The site goes live at `https://katsuma0.github.io/makozumi/`.

## Writing a tag to an NFC chip

1. Open `generate.html`, paste your private key JWK, fill in the product fields,
   and copy the generated URL. (Or use the sample URL below for the first product.)
2. On your phone, install **NFC Tools** (iOS/Android).
3. **Write → Add a record → URL/URI** → paste the tag URL → **Write** → hold the
   blank tag to the phone.
4. Tap the tag with any phone to test: the verifier should open and show ✓ AUTHENTIC.

Tag URLs are ~250–300 characters. Use **NTAG215** (504 bytes) or **NTAG216**
chips; NTAG213 (144 bytes) is too small.

## Tag format

```
https://katsuma0.github.io/makozumi/#<base64url(payload)>.<base64url(signature)>
```

- **payload** — compact JSON: `{"v":1,"sn":"MKZ-0001","p":"<product>","t":"<type>","o":"<maker>","d":"YYYY-MM-DD"}`
- **signature** — 64-byte ECDSA P-256 signature (r‖s, IEEE P1363) over the
  base64url payload string, hashed with SHA-256.

The data rides in the URL *fragment* (`#…`), so it is never sent to any server —
verification is fully client-side.

## Key management (important)

- The **public key** is embedded in `index.html`. It can only *verify*.
- The **private key** is *not in this repository* and must never be committed.
  Store the private JWK somewhere safe (password manager). If it ever leaks,
  generate a new pair, update the public key in `index.html`, and re-issue tags.

## First product

Serial `MKZ-0001` — *Katsuma 2026 Log* (notebook) by Katsuma Onishi, issued
2026-08-06. Its signed tag URL is in [`samples/MKZ-0001.txt`](samples/MKZ-0001.txt).
