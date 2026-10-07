# Alphabros Router (Solana)

A fee router for swaps on Solana (Alphabros V4). Users swap through the venue they choose and pay an exact fee in SOL;
the fee is shared between the protocol and the community and/or referral the trade names. Same rules as the Alphabros
V4 router on EVM chains (`0xF5502aa596cDA6705EB3ADd95BcA44C7c367de90`, one address on every chain).

**Program (mainnet-beta):** `9Gv5FLbNg4iKEDK9dM7twBrCjc65KEMpthG3SoYq53Aa`

## How it works

- **Fee** = max(floor, SOL side × fee rate), measured on what actually moved (the SOL side is the wSOL account's change
  plus the wallet's change, signed), charged in SOL after the swap, never above the `max_fee` the user signed. The
  owner sets the rate, never above **0.5%** (a constant).
- **Payee share**: one share of the fee, set by the owner and never above **60%** (a constant), goes whole to the
  community or the referral a trade names, split by the owner's community split when it names both. A payee whose
  wallet is the trader or the protocol wallet earns nothing; the protocol keeps the rest (at least 40%).
- **One signature for every chain**: a community or referral registers with an EIP-712 `Registration(kind, owner,
  name, wallet, solanaWallet, version)` signed by its owner's EVM key, the same message the EVM router checks (domain
  "Alphabros" / "4" / the EVM router address, no chain ID). Its ID is `keccak(kind, owner, name)` everywhere, so
  nobody else can claim it; `register_payee` (anyone may send it) stores it; only a higher `version` changes its
  wallet. Each trade states the payout wallet it expects for each payee and reverts on any mismatch (`PayeeMismatch`).
- **Every swap has wSOL on one side** (`UnpricedPair`), spends something from the measured input (`ZeroInput`), never
  more than `max_input` (`InputTooHigh`), and returns at least `min_out` (`InsufficientOutput`).
- **Venues are permissionless.** The user signs the transaction and so chooses the venue (Jupiter v6, another
  aggregator, a DEX, a bonding curve). What makes a venue safe to call is what `execute_v4` enforces around it:
  - no other writable token account the user owns, delegates or can close may reach the swap
    (`SwapAccountNotBound`), and no SPL multisig (`MultisigNotAllowed`);
  - no writable mint naming the user as any authority (base or Token-2022 extension), and no other account of a mint
    through which the user can act on accounts it does not own: freeze, permanent delegate, withdraw-withheld,
    confidential approval (`AuthorityExposed`);
  - no writable account a native program owns, nor a system account holding data such as a durable nonce
    (`ProtectedAccount`);
  - only the user's signature is passed on; the wallet is read-only unless the user signs `max_wallet_spend` (at most
    100 SOL, for venues that trade the wallet's own SOL), and then it must stay a plain system account
    (`WalletTampered`) that lost at most that amount (`WalletSpendTooHigh`);
  - the owner, delegate and close authority of both measured accounts are unchanged afterwards
    (`AccountAuthorityChanged`), and neither loses lamports beyond its token amount (`AccountLamportsTaken`);
  - the router itself and the native programs are never venues (`VenueNotAllowed`); for Jupiter v6 the instruction
    must be a route (`JupiterNotARoute`) with Jupiter's own platform fee off (`JupiterPlatformFee`).

  A venue can still act on other programs' accounts the user hands it and signs for: the user's choice of venue is the
  trust boundary.
- Fees are credited inside the program; `collect_v4` (protocol) and `collect_payee` (community / referral) pay each
  wallet what it earned. Anyone may trigger them; the SOL only ever goes to that wallet.

## Who can change what

| Setting | Who | Notes |
| --- | --- | --- |
| Fee rate cap (0.5%), payee share cap (60%), floor cap | nobody | constants / fixed at `initialize_v4` |
| Fee rate, payee share, community split, floor | owner | within the caps; applies to fees settled afterwards |
| Protocol fee wallet | owner | credits already earned stay with the old wallet |
| A community's / referral's payout wallet | its owner (EVM signature) | a higher `version` only |
| Ownership | current owner | two steps: `transfer_ownership_v4`, then `accept_ownership_v4` |

Nobody can move a user's tokens except through that user's own swap, or move anyone's credit.

## Layout

| Path | What |
| --- | --- |
| `programs/alphabros_router` | The program (Anchor 1.2.0): the only thing deployed |
| `programs/mock_swap` | Test-only venues: a set swap, a bonding curve, and hostile `relay` venues that do whatever a test asks with the user's signature |
| `tests/tests/router.rs` | Swap safety, fees, owner settings, collection (LiteSVM, against the compiled programs) |
| `tests/tests/v4.rs` | Payees: EIP-712 parity with the EVM router, registration, the share split, collect |
| `tests/tests/jupiter_fork.rs` | Real Jupiter routes on real mainnet state (snapshots from `live/jupiter-snapshot.mjs`; skipped without them) |
| `.github/workflows/verifiable-build.yml` | Reproducible build with `solana-verify`, tests against that binary, IDL |

## Build, test, verify

```sh
# Reproducible build (Docker; image pinned in Cargo.toml [workspace.metadata.cli]):
solana-verify build --library-name alphabros_router
solana-verify get-executable-hash target/deploy/alphabros_router.so

# Compare with the deployed program:
solana-verify get-program-hash -u mainnet-beta 9Gv5FLbNg4iKEDK9dM7twBrCjc65KEMpthG3SoYq53Aa

# Tests (LiteSVM; stable Rust >= 1.97.1), after building both programs into target/deploy:
cd tests && cargo test --test router --test v4

# Optional mainnet-fork tests: snapshot real Jupiter routes (needs SOLANA_MAINNET_RPC_URL in a local .env), then
cd live && npm install && node jupiter-snapshot.mjs && cd ../tests && cargo test --test jupiter_fork
```

## License

MIT
