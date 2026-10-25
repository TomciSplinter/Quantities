// Quantities SDK — Winternitz one-time signatures and vault instructions.
// Mirrors program/src/wots.rs and program/src/lib.rs byte for byte.
// Works in Node (npm deps) and in the browser (via the import map in app/index.html).

import { sha256 } from '@noble/hashes/sha2';
import { Buffer } from 'buffer';
import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  ComputeBudgetProgram,
} from '@solana/web3.js';

export const N = 28;
export const MSG_DIGITS = 28;
export const CHAINS = 30;
export const MAX_STEP = 255;
export const SIGNATURE_LEN = CHAINS * N;
export const COMPUTE_UNITS = 1_400_000;

const enc = new TextEncoder();
const VAULT_SEED = enc.encode('quantities');
const SPLIT_DOMAIN = enc.encode('quantities:split:v1');
const CLOSE_DOMAIN = enc.encode('quantities:close:v1');
const SK_DOMAIN = enc.encode('quantities-wots-sk');
const DERIVE_DOMAIN = enc.encode('quantities-vault');

function concat(...parts) {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const hashv = (...parts) => sha256(concat(...parts));

function u64le(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

// ---- WOTS -----------------------------------------------------------------

// One chain step: SHA256(x || chain || step)[..28]
const step = (x, chain, j) => sha256(concat(x, Uint8Array.of(chain, j))).slice(0, N);

export function chain(x, i, from, to) {
  let v = x;
  for (let j = from; j < to; j++) v = step(v, i, j);
  return v;
}

export function digits(message) {
  const d = new Uint8Array(CHAINS);
  let checksum = 0;
  for (let i = 0; i < MSG_DIGITS; i++) {
    d[i] = message[i];
    checksum += MAX_STEP - message[i];
  }
  d[MSG_DIGITS] = checksum >> 8;
  d[MSG_DIGITS + 1] = checksum & 0xff;
  return d;
}

export function privateKey(seed) {
  return Array.from({ length: CHAINS }, (_, i) => hashv(SK_DOMAIN, seed, Uint8Array.of(i)).slice(0, N));
}

export const publicKey = (sk) => sk.map((s, i) => chain(s, i, 0, MAX_STEP));
export const root = (pk) => hashv(...pk);

export function sign(sk, message) {
  const d = digits(message);
  const out = new Uint8Array(SIGNATURE_LEN);
  sk.forEach((s, i) => out.set(chain(s, i, 0, d[i]), i * N));
  return out;
}

export function recoverRoot(signature, message) {
  if (signature.length !== SIGNATURE_LEN) return null;
  const d = digits(message);
  const pk = [];
  for (let i = 0; i < CHAINS; i++) pk.push(chain(signature.slice(i * N, (i + 1) * N), i, d[i], MAX_STEP));
  return root(pk);
}

// ---- Vaults ---------------------------------------------------------------

/** Seed for the vault at `index` of a 32-byte master secret. */
export const vaultSeed = (master, index) => {
  const i = new Uint8Array(4);
  new DataView(i.buffer).setUint32(0, index, true);
  return hashv(DERIVE_DOMAIN, master, i);
};

export function findVault(rootBytes, programId) {
  const [address, bump] = PublicKey.findProgramAddressSync([VAULT_SEED, rootBytes], new PublicKey(programId));
  return { address, bump };
}

/** Everything needed to use vault number `index`. */
export function deriveVault(master, index, programId) {
  const sk = privateKey(vaultSeed(master, index));
  const r = root(publicKey(sk));
  return { index, sk, root: r, ...findVault(r, programId) };
}

export const splitMessage = (vault, amount, destination, refund) =>
  hashv(SPLIT_DOMAIN, new PublicKey(vault).toBytes(), u64le(amount),
    new PublicKey(destination).toBytes(), new PublicKey(refund).toBytes());

export const closeMessage = (vault, destination) =>
  hashv(CLOSE_DOMAIN, new PublicKey(vault).toBytes(), new PublicKey(destination).toBytes());

const budget = () => ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNITS });

/** Instructions to send `amount` lamports to `destination` and the rest to `refund`. */
export function splitInstructions({ programId, vault, amount, destination, refund }) {
  const msg = splitMessage(vault.address, amount, destination, refund);
  const data = concat(Uint8Array.of(0, vault.bump), u64le(amount), sign(vault.sk, msg));
  return [budget(), new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: vault.address, isSigner: false, isWritable: true },
      { pubkey: new PublicKey(destination), isSigner: false, isWritable: true },
      { pubkey: new PublicKey(refund), isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  })];
}

/** Instructions to send the whole vault balance to `destination`. */
export function closeInstructions({ programId, vault, destination }) {
  const msg = closeMessage(vault.address, destination);
  const data = concat(Uint8Array.of(1, vault.bump), sign(vault.sk, msg));
  return [budget(), new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: [
      { pubkey: vault.address, isSigner: false, isWritable: true },
      { pubkey: new PublicKey(destination), isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  })];
}

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const fromHex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
