// Snapshots real Jupiter v6 routes from mainnet for the LiteSVM fork test (tests/tests/jupiter_fork.rs).
//
//   node live/jupiter-snapshot.mjs
//
// For each scenario: asks Jupiter's API for a quote and the swap instruction (for a fresh test user, SOL wrapping
// off), then downloads every account that instruction touches from the mainnet RPC in .env (SOLANA_MAINNET_RPC_URL),
// including the lookup tables it uses and, for programs, their executable code (program data). Accounts that do not
// exist yet (the user's token accounts) are listed as missing; the test creates them. Snapshots go to
// live/snapshots/<name>.json (git-ignored: they contain whole program binaries).
import fs from "node:fs";
import crypto from "node:crypto";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";

const env = Object.fromEntries(
  fs.readFileSync(new URL("../.env", import.meta.url), "utf8").split(/\r?\n/)
    .map((l) => l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)).filter(Boolean)
    .map((m) => [m[1], m[2].replace(/^["']|["']$/g, "")]),
);
const RPC = env.SOLANA_MAINNET_RPC_URL;
if (!RPC) throw new Error("SOLANA_MAINNET_RPC_URL is empty in .env");
const JUP_API = env.JUPITER_API_URL || "https://lite-api.jup.ag/swap/v1";
const headers = { "Content-Type": "application/json", ...(env.JUPITER_API_KEY ? { "x-api-key": env.JUPITER_API_KEY } : {}) };
const conn = new Connection(RPC, "confirmed");

const WSOL = "So11111111111111111111111111111111111111112";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const JUP = "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN";
const LOADER_V3 = "BPFLoaderUpgradeab1e11111111111111111111111";
// Classic pool-based DEXes replay deterministically from a snapshot; proprietary market makers (BisonFi, Obsidian,
// ...) re-price every slot and often refuse a replay, so the main scenarios are restricted to classic pools.
const CLASSIC = "Whirlpool,Raydium CLMM,Meteora DLMM,Raydium";
const SCENARIOS = [
  { name: "sol_to_usdc", input: WSOL, output: USDC, amount: 1_000_000_000, direct: true, dexes: "Whirlpool" },
  { name: "usdc_to_sol", input: USDC, output: WSOL, amount: 100_000_000, direct: true, dexes: "Raydium CLMM,Meteora DLMM" },
  { name: "sol_to_jup_multihop", input: WSOL, output: JUP, amount: 1_000_000_000, direct: false, dexes: CLASSIC },
  // A genuine two-hop route: SOL -> USDC -> BONK, both legs on Raydium CLMM.
  { name: "sol_to_bonk_two_hops", input: WSOL, output: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", amount: 1_000_000_000, direct: false, dexes: "Raydium CLMM,Meteora DLMM,Raydium" },
].filter((s) => process.argv.length <= 2 || process.argv.slice(2).includes(s.name));

const OUTDIR = new URL("./snapshots/", import.meta.url);
fs.mkdirSync(OUTDIR, { recursive: true });

async function jup(path, init) {
  const r = await fetch(`${JUP_API}${path}`, { headers, ...init });
  const text = await r.text();
  if (!r.ok) throw new Error(`Jupiter ${path}: ${r.status} ${text.slice(0, 300)}`);
  return JSON.parse(text);
}

async function fetchAccounts(keys) {
  const out = {};
  let slot = 0;
  for (let i = 0; i < keys.length; i += 100) {
    const batch = keys.slice(i, i + 100).map((k) => new PublicKey(k));
    const res = await conn.getMultipleAccountsInfoAndContext(batch);
    slot = Math.max(slot, res.context.slot);
    res.value.forEach((a, j) => {
      if (a) out[batch[j].toBase58()] = { lamports: a.lamports, owner: a.owner.toBase58(), executable: a.executable, data: a.data.toString("base64") };
    });
  }
  return { out, slot };
}

async function snapshot(sc) {
  const user = Keypair.fromSeed(crypto.createHash("sha256").update(`alphabros-fork-user-${sc.name}`).digest());
  const quote = await jup(`/quote?inputMint=${sc.input}&outputMint=${sc.output}&amount=${sc.amount}&slippageBps=100${sc.direct ? "&onlyDirectRoutes=true" : ""}&maxAccounts=40${sc.dexes ? `&dexes=${encodeURIComponent(sc.dexes)}` : ""}`);
  const swap = await jup("/swap-instructions", {
    method: "POST",
    body: JSON.stringify({ quoteResponse: quote, userPublicKey: user.publicKey.toBase58(), wrapAndUnwrapSol: false, skipUserAccountsRpcCalls: true, dynamicComputeUnitLimit: false }),
  });
  const ix = swap.swapInstruction;
  const alts = swap.addressLookupTableAddresses ?? [];
  const keys = [...new Set([...ix.accounts.map((a) => a.pubkey), ix.programId, ...alts, sc.input, sc.output])];
  let { out: accounts, slot } = await fetchAccounts(keys);

  // Program code: each upgradeable program's data account (bytes 4..36 of the program account).
  const pdKeys = Object.entries(accounts)
    .filter(([, a]) => a.executable && a.owner === LOADER_V3)
    .map(([, a]) => new PublicKey(Buffer.from(a.data, "base64").subarray(4, 36)).toBase58());
  const pd = await fetchAccounts(pdKeys);
  Object.assign(accounts, pd.out);

  const mintOwner = (m) => new PublicKey(accounts[m].owner);
  const userIn = getAssociatedTokenAddressSync(new PublicKey(sc.input), user.publicKey, false, mintOwner(sc.input)).toBase58();
  const userOut = getAssociatedTokenAddressSync(new PublicKey(sc.output), user.publicKey, false, mintOwner(sc.output)).toBase58();
  const missing = keys.filter((k) => !accounts[k]);
  const blockTime = await conn.getBlockTime(slot).catch(() => null);

  const snap = {
    name: sc.name, slot, unixTime: blockTime ?? Math.floor(Date.now() / 1000), takenAt: new Date().toISOString(),
    userSeed: Buffer.from(user.secretKey.subarray(0, 32)).toString("base64"), user: user.publicKey.toBase58(),
    input: sc.input, output: sc.output, inputTokenProgram: accounts[sc.input].owner, outputTokenProgram: accounts[sc.output].owner,
    userIn, userOut, amount: String(sc.amount),
    quote: { outAmount: quote.outAmount, otherAmountThreshold: quote.otherAmountThreshold, priceImpactPct: quote.priceImpactPct,
      route: quote.routePlan.map((r) => `${r.swapInfo.label} ${r.swapInfo.inputMint.slice(0, 4)}->${r.swapInfo.outputMint.slice(0, 4)}`) },
    swapIx: { programId: ix.programId, accounts: ix.accounts, data: ix.data },
    alts, missing, accounts,
  };
  const file = new URL(`./${sc.name}.json`, OUTDIR);
  fs.writeFileSync(file, JSON.stringify(snap));
  const size = (fs.statSync(file).size / 1e6).toFixed(1);
  console.log(`${sc.name}: ${snap.quote.route.join(" | ")}; out ${quote.outAmount} (min ${quote.otherAmountThreshold}); ` +
    `${ix.accounts.length} ix accounts, ${alts.length} lookup tables, ${Object.keys(accounts).length} accounts fetched, missing [${missing.length}], slot ${slot}, ${size} MB`);
}

for (const sc of SCENARIOS) {
  try {
    await snapshot(sc);
  } catch (e) {
    console.log(`${sc.name}: FAILED ${String(e?.message ?? e).slice(0, 300)}`);
  }
}
