// Checks the SDK matches the Rust program byte for byte (vectors from
// `cargo test cross_language_vectors -- --nocapture`).
import assert from 'node:assert/strict';
import { PublicKey, Transaction, Keypair } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2';
import * as q from './index.js';

const seed = new Uint8Array(32).fill(1);
const program = new PublicKey(new Uint8Array(32).fill(9));
const sk = q.privateKey(seed);
const r = q.root(q.publicKey(sk));
const { address, bump } = q.findVault(r, program);
const msg = q.splitMessage(address, 1_000_000, new PublicKey(new Uint8Array(32).fill(2)), new PublicKey(new Uint8Array(32).fill(3)));
const sig = q.sign(sk, msg);

assert.equal(q.toHex(r), '7b6200760dba454bf7a68c972031760eda342431f3eedf96c4ae984416a90cfb');
assert.equal(address.toBase58(), '7yfPY5RJne7D69fgXuGkCyNmjx8Bya2C4GrauqkntDTK');
assert.equal(bump, 255);
assert.equal(q.toHex(msg), '80716c9bd28380b4c6b486d504247ca289ac3ac423680caa3d84baa19a07eb39');
assert.equal(q.toHex(sha256(sig)), 'e895a92c3064e743cac292d4f401e9f8f38b84fd520897296dd0615c03a61e2d');
assert.equal(q.toHex(q.recoverRoot(sig, msg)), q.toHex(r));

// A real split transaction must fit Solana's 1232-byte packet limit.
const payer = Keypair.generate();
const vault = q.deriveVault(new Uint8Array(32).fill(4), 0, program);
const next = q.deriveVault(new Uint8Array(32).fill(4), 1, program);
const tx = new Transaction({ feePayer: payer.publicKey, recentBlockhash: PublicKey.default.toBase58() })
  .add(...q.splitInstructions({ programId: program, vault, amount: 5, destination: Keypair.generate().publicKey, refund: next.address }));
tx.sign(payer);
const size = tx.serialize().length;
console.log('split tx size:', size, 'bytes');
assert.ok(size <= 1232);
console.log('all SDK checks passed');
