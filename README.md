# Quantities

Quantum-resistant SOL vaults on Solana.

Normal Solana accounts are protected by Ed25519, an elliptic-curve signature that a large enough quantum computer could break. A Quantities vault is a program-derived address whose only key is a **Winternitz one-time signature (WOTS)** built purely from SHA-256. Hash-based signatures are believed to stay secure against quantum attacks.

## How it works

- **Vault address** = PDA of `["quantities", root, bump]`, where `root` is the hash of a WOTS public key. There's no Ed25519 key for the vault at all.
- **Deposit**: a plain SOL transfer to the vault address. Anyone can deposit.
- **Spend**: you sign the exact destinations with the one-time key. The program recomputes the public key from the signature, derives the vault address from it and checks it matches.
- **One key, one spend**: a WOTS signature reveals part of the key, so every spend drains the vault. `Split` sends an amount to the destination and the change to your next vault. `Close` sends everything to one address.
- Your wallet (Phantom, Solflare) only pays the transaction fee. It has no authority over the vault.

### Parameters

| | |
|---|---|
| Hash | SHA-256 truncated to 224 bits, tweaked with chain and step index |
| Winternitz w | 256 (one byte per digit) |
| Chains | 28 message + 2 checksum = 30 |
| Signature | 840 bytes |
| Split tx size | 1192 of 1232 bytes |
| Compute | ~570k–730k CU typical (LiteSVM); worst case ~1.15M, so the budget is set to the 1.4M maximum |

## Layout

```
program/   Rust on-chain program (native, no Anchor) + WOTS + unit tests
sdk/       JavaScript SDK (Node and browser): keys, signing, instructions
app/       Web app: vault balance, deposit, send, send all
tests/     LiteSVM integration tests against the compiled program
scripts/   build-web.mjs packs the app, SDK and images into dist/ for hosting
vercel.json  Vercel build settings for the website
```

## Build and test

```bash
# program
cd program
cargo test                 # WOTS unit tests + cross-language vectors
cargo build-sbf            # produces target/deploy/quantities.so (a prebuilt copy is in deploy/)

# integration (needs the .so above)
cd ../tests && cargo run --release

# sdk
cd ../sdk && npm install && npm test
```

## Deploy (devnet first)

```bash
solana config set --url devnet
solana airdrop 5
cd program && solana program deploy deploy/quantities.so --program-id deploy/quantities-keypair.json
```

Put the printed program ID into `DEFAULTS.program` in `app/index.html` (or paste it in the app's settings).

The program keypair in `program/deploy/` is gitignored. Keep a private copy: until the program is deployed, anyone holding it could claim the program address.

## Run the app locally

```bash
node scripts/build-web.mjs && npx serve dist     # then open the printed localhost URL
```

## Deploy the website on Vercel

The site is static. `vercel.json` makes Vercel run `node scripts/build-web.mjs` (no dependencies, no environment variables) and serve `dist/`.

- **From GitHub (works from a phone):** push this repo to GitHub, then in Vercel choose **Add New → Project**, import the repo and press **Deploy**. Every push redeploys.
- **From a computer:** in this folder run `npx vercel` (log in and accept the defaults) for a preview deployment, then `npx vercel --prod` for your production URL.

Deploy the program (above) to the network the site uses first. Until then, balances and deposits work but sending fails because the program doesn't exist there. The site defaults to devnet; for mainnet, change `DEFAULTS` in `app/index.html` or the RPC and program ID in the app's settings.

The app keeps a 32-byte master secret in the browser's local storage. Vault *n* uses the key derived from `SHA256("quantities-vault" || secret || n)`. **Back up the secret** — it's the only way to spend.

The interface is themed on the QUANT mascot: `app/assets/` holds the mascot portrait and avatar, the |0⟩ / |1⟩ qubit orbs switch between Deposit and Send, and the Signature panel draws each signature's 30 hash-chain positions.

**One-time-key lock.** As soon as a signed transfer is handed to the wallet, the app locks that vault to that exact transfer (stored per vault address). If it fails or is declined, the vault can only retry the identical transfer, because two different WOTS signatures from one key let an attacker forge a third. A release button in settings exists for the case where the transfer provably never left the wallet. Without a wallet or network, Send runs as a local dry run that signs, draws the chains and sends nothing.

## Before mainnet

This is a working prototype, not an audited product.

- Get an independent security audit of the program and the WOTS implementation.
- Never sign two different transfers with the same vault. The app moves to the next vault after every spend and locks a vault to its first signed transfer; if you restore an old secret on a new device, set the vault number past any vault already used, since the lock lives in the old browser.
- A split must leave at least the rent-exempt minimum (~0.00089 SOL) as change, or use Send entire balance.
- The fee payer is still an Ed25519 wallet. A quantum attacker could steal that wallet's fee SOL, but never the vault's funds.
- Mainnet launch: make the program immutable (`solana program set-upgrade-authority --final`) or put the upgrade key behind a multisig, since an upgradable program is the weakest link.
